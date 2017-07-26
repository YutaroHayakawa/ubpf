#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#include "ubpf_int.h"

enum {
  DISCOVERED = 0x10,
  EXPLORED = 0x20,
  FALLTHROUGH = 1,
  BRANCH = 2,
};

static int *inst_stack;  /* stack of insns to process */
static int stack_ptr;  /* current stack index */
static int *inst_state;

static int push_inst(int t, int w, int e, uint32_t num_insts, char **errmsg) {
  if (e == FALLTHROUGH && inst_state[t] >= (DISCOVERED | FALLTHROUGH))
    return 0;

  if (e == BRANCH && inst_state[t] >= (DISCOVERED | BRANCH))
    return 0;

  if (w < 0 || w >= num_insts) {
    *errmsg = ubpf_error("jump out of range from insn %d to %d", t, w);
    return -EINVAL;
  }

  if (inst_state[w] == 0) {
    /* tree-edge */
    inst_state[t] = DISCOVERED | e;
    inst_state[w] = DISCOVERED;
    if (stack_ptr >= num_insts) {
      return -E2BIG;
    }
    inst_stack[stack_ptr++] = w;
    return 1;
  } else if ((inst_state[w] & 0xF0) == DISCOVERED) {
    *errmsg = ubpf_error("back-edge from insn %d to %d", t, w);
    return -EINVAL;
  } else if (inst_state[w] == EXPLORED) {
    /* forward- or cross-edge */
    inst_state[t] = DISCOVERED | e;
  } else {
    *errmsg = ubpf_error("insn state internal bug");
    return -EFAULT;
  }
  return 0;
}

static int detect_loop(const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg) {
  inst_state = calloc(num_insts, sizeof(int));
  if (!inst_state) {
    *errmsg = ubpf_error("%s", strerror(ENOMEM));
    return -ENOMEM;
  }

  inst_stack = calloc(num_insts, sizeof(int));
  if (!inst_stack) {
    free(inst_state);
    *errmsg = ubpf_error("%s", strerror(ENOMEM));
    return -ENOMEM;
  }

  inst_state[0] = DISCOVERED; /* mark 1st insn as discovered */
  inst_stack[0] = 0; /* 0 is the first instruction */
  stack_ptr = 1;

  int cur, ret;
  uint8_t op;
  while (stack_ptr != 0) {
    cur = inst_stack[stack_ptr - 1];
    stack_ptr--;

    op = insts[cur].opcode;
    if ((op & EBPF_CLS_MASK) == EBPF_CLS_JMP) {
      if (op == EBPF_OP_EXIT) {
        continue;
      } else if (op == EBPF_OP_CALL) {
        ret = push_inst(cur, cur + 1, FALLTHROUGH, num_insts, errmsg);
        if (ret == 1) {
          break;
        } else if (ret < 0) {
          goto err;
        }
        continue;
      } else if (op == EBPF_OP_JA) {
        if (insts[cur].src != 0x00) {
          ret = -EINVAL;
          goto err;
        }
        ret = push_inst(cur, cur + insts[cur].offset + 1,
            FALLTHROUGH, num_insts, errmsg);
        if (ret == 1) {
          continue;
        } else if (ret < 0) {
          goto err;
        }
      } else {
        ret = push_inst(cur, cur + 1, FALLTHROUGH, num_insts, errmsg);
        if (ret == 1) {
          continue;
        } else if (ret < 0) {
          goto err;
        }
        ret = push_inst(cur, cur + insts[cur].offset + 1, BRANCH, num_insts, errmsg);
        if (ret == 1) {
          continue;
        } else if (ret < 0) {
          goto err;
        }
        continue;
      }
    } else {
      ret = push_inst(cur, cur + 1, FALLTHROUGH, num_insts, errmsg);
      if (ret == 1) {
        continue;
      } else if (ret < 0) {
        goto err;
      }
    }

    inst_state[cur] = EXPLORED;
    if (stack_ptr-- <= 0) {
      *errmsg = ubpf_error("pop stack internal bug");
      ret = -EFAULT;
      goto err;
    }
  }

  for (uint32_t i = 0; i < num_insts; i++) {
    if (inst_state[i] != EXPLORED) {
      *errmsg = ubpf_error("unreachable inst %d", i);
      ret = -EINVAL;
      goto err;
    }
  }

  ret = 0;

err:
  free(inst_state);
  free(inst_stack);
  return ret;
}

enum ubpf_reg_type {
  NOT_INIT = 0,
  UNKNOWN_VALUE,
  FRAME_PTR,
  PTR_TO_STACK,
  CONST_IMM,
  PTR_TO_NM_BDG_FWD,
  PTR_TO_FT_BUF,
  PTR_TO_FT_LEN,
  PTR_TO_DST_RING,
  PTR_TO_NM_VP_ADAPTER
};

struct ubpf_reg_state {
  enum ubpf_reg_type type;
  union {
    int64_t imm;
    struct {
      uint16_t offset;
      uint16_t range;
    };
  };
  int64_t min_value;
  uint64_t max_value;
  uint32_t min_align;
  uint32_t aux_off;
  uint32_t aux_off_align;
};

static void init_reg_state(struct ubpf_reg_state *regs) {
  for (int i = 0; i < 10; i++) {
    memset(&regs[i], 0, sizeof(regs[i]));
    regs[i].type = NOT_INIT;
    regs[i].min_value = INT64_MIN;
    regs[i].max_value = UINT64_MAX;
  }

  regs[10] = FRAME_PTR;
  regs[1] = PTR_TO_NM_BDG_FWD;
  regs[2] = PTR_TO_DST_RING;
  regs[3] = PTR_TO_NM_VP_ADAPTER;
}

int type_tracking(const struct ebpf_inst *insts, uint32_t num_insts) {
  struct ubpf_reg_state regs[10];
  init_reg_state(regs);

  for (int i = 0; i < num_insts; i++) {
    struct ebpf_inst *inst = &insts[i];
    int new_pc;
    bool store = false;

    switch (inst.opcode) {
      case EBPF_OP_ADD_IMM:
      case EBPF_OP_ADD_REG:
      case EBPF_OP_SUB_IMM:
      case EBPF_OP_SUB_REG:
      case EBPF_OP_MUL_IMM:
      case EBPF_OP_MUL_REG:
      case EBPF_OP_DIV_REG:
      case EBPF_OP_OR_IMM:
      case EBPF_OP_OR_REG:
      case EBPF_OP_AND_IMM:
      case EBPF_OP_AND_REG:
      case EBPF_OP_LSH_IMM:
      case EBPF_OP_LSH_REG:
      case EBPF_OP_RSH_IMM:
      case EBPF_OP_RSH_REG:
      case EBPF_OP_NEG:
      case EBPF_OP_MOD_REG:
      case EBPF_OP_XOR_IMM:
      case EBPF_OP_XOR_REG:
      case EBPF_OP_MOV_IMM:
      case EBPF_OP_MOV_REG:
      case EBPF_OP_ARSH_IMM:
      case EBPF_OP_ARSH_REG:
          break;

      case EBPF_OP_LE:
      case EBPF_OP_BE:
          break;

      case EBPF_OP_ADD64_IMM:
      case EBPF_OP_ADD64_REG:
      case EBPF_OP_SUB64_IMM:
      case EBPF_OP_SUB64_REG:
      case EBPF_OP_MUL64_IMM:
      case EBPF_OP_MUL64_REG:
      case EBPF_OP_DIV64_REG:
      case EBPF_OP_OR64_IMM:
      case EBPF_OP_OR64_REG:
      case EBPF_OP_AND64_IMM:
      case EBPF_OP_AND64_REG:
      case EBPF_OP_LSH64_IMM:
      case EBPF_OP_LSH64_REG:
      case EBPF_OP_RSH64_IMM:
      case EBPF_OP_RSH64_REG:
      case EBPF_OP_NEG64:
      case EBPF_OP_MOD64_REG:
      case EBPF_OP_XOR64_IMM:
      case EBPF_OP_XOR64_REG:
      case EBPF_OP_MOV64_IMM:
      case EBPF_OP_MOV64_REG:
      case EBPF_OP_ARSH64_IMM:
      case EBPF_OP_ARSH64_REG:
          break;

      case EBPF_OP_LDXW:
      case EBPF_OP_LDXH:
      case EBPF_OP_LDXB:
      case EBPF_OP_LDXDW:
          break;

      case EBPF_OP_STW:
      case EBPF_OP_STH:
      case EBPF_OP_STB:
      case EBPF_OP_STDW:
      case EBPF_OP_STXW:
      case EBPF_OP_STXH:
      case EBPF_OP_STXB:
      case EBPF_OP_STXDW:
          store = true;
          break;

      case EBPF_OP_LDDW:
          break;

      case EBPF_OP_JA:
      case EBPF_OP_JEQ_REG:
      case EBPF_OP_JEQ_IMM:
      case EBPF_OP_JGT_REG:
      case EBPF_OP_JGT_IMM:
      case EBPF_OP_JGE_REG:
      case EBPF_OP_JGE_IMM:
      case EBPF_OP_JSET_REG:
      case EBPF_OP_JSET_IMM:
      case EBPF_OP_JNE_REG:
      case EBPF_OP_JNE_IMM:
      case EBPF_OP_JSGT_IMM:
      case EBPF_OP_JSGT_REG:
      case EBPF_OP_JSGE_IMM:
      case EBPF_OP_JSGE_REG:
          break;

      case EBPF_OP_CALL:
          break;

      case EBPF_OP_EXIT:
          break;

      case EBPF_OP_DIV_IMM:
      case EBPF_OP_MOD_IMM:
      case EBPF_OP_DIV64_IMM:
      case EBPF_OP_MOD64_IMM:
          break;

      default:
          return false;
    }
  }
}

bool validate(const struct ubpf_vm *vm, const struct ebpf_inst *insts,
    uint32_t num_insts, char **errmsg) {
  int err;

  err = detect_loop(insts, num_insts, errmsg);
  if (err < 0) {
    return false;
  }

  if (num_insts >= MAX_INSTS) {
      *errmsg = ubpf_error("too many instructions (max %u)", MAX_INSTS);
      return false;
  }

  if (num_insts == 0 || insts[num_insts-1].opcode != EBPF_OP_EXIT) {
      *errmsg = ubpf_error("no exit at end of instructions");
      return false;
  }

  int i;
  for (i = 0; i < num_insts; i++) {
      struct ebpf_inst inst = insts[i];
      int new_pc;
      bool store = false;

      switch (inst.opcode) {
      case EBPF_OP_ADD_IMM:
      case EBPF_OP_ADD_REG:
      case EBPF_OP_SUB_IMM:
      case EBPF_OP_SUB_REG:
      case EBPF_OP_MUL_IMM:
      case EBPF_OP_MUL_REG:
      case EBPF_OP_DIV_REG:
      case EBPF_OP_OR_IMM:
      case EBPF_OP_OR_REG:
      case EBPF_OP_AND_IMM:
      case EBPF_OP_AND_REG:
      case EBPF_OP_LSH_IMM:
      case EBPF_OP_LSH_REG:
      case EBPF_OP_RSH_IMM:
      case EBPF_OP_RSH_REG:
      case EBPF_OP_NEG:
      case EBPF_OP_MOD_REG:
      case EBPF_OP_XOR_IMM:
      case EBPF_OP_XOR_REG:
      case EBPF_OP_MOV_IMM:
      case EBPF_OP_MOV_REG:
      case EBPF_OP_ARSH_IMM:
      case EBPF_OP_ARSH_REG:
          break;

      case EBPF_OP_LE:
      case EBPF_OP_BE:
          if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
              *errmsg = ubpf_error("invalid endian immediate at PC %d", i);
              return false;
          }
          break;

      case EBPF_OP_ADD64_IMM:
      case EBPF_OP_ADD64_REG:
      case EBPF_OP_SUB64_IMM:
      case EBPF_OP_SUB64_REG:
      case EBPF_OP_MUL64_IMM:
      case EBPF_OP_MUL64_REG:
      case EBPF_OP_DIV64_REG:
      case EBPF_OP_OR64_IMM:
      case EBPF_OP_OR64_REG:
      case EBPF_OP_AND64_IMM:
      case EBPF_OP_AND64_REG:
      case EBPF_OP_LSH64_IMM:
      case EBPF_OP_LSH64_REG:
      case EBPF_OP_RSH64_IMM:
      case EBPF_OP_RSH64_REG:
      case EBPF_OP_NEG64:
      case EBPF_OP_MOD64_REG:
      case EBPF_OP_XOR64_IMM:
      case EBPF_OP_XOR64_REG:
      case EBPF_OP_MOV64_IMM:
      case EBPF_OP_MOV64_REG:
      case EBPF_OP_ARSH64_IMM:
      case EBPF_OP_ARSH64_REG:
          break;

      case EBPF_OP_LDXW:
      case EBPF_OP_LDXH:
      case EBPF_OP_LDXB:
      case EBPF_OP_LDXDW:
          break;

      case EBPF_OP_STW:
      case EBPF_OP_STH:
      case EBPF_OP_STB:
      case EBPF_OP_STDW:
      case EBPF_OP_STXW:
      case EBPF_OP_STXH:
      case EBPF_OP_STXB:
      case EBPF_OP_STXDW:
          store = true;
          break;

      case EBPF_OP_LDDW:
          if (i + 1 >= num_insts || insts[i+1].opcode != 0) {
              *errmsg = ubpf_error("incomplete lddw at PC %d", i);
              return false;
          }
          i++; // Skip next instruction
          break;

      case EBPF_OP_JA:
      case EBPF_OP_JEQ_REG:
      case EBPF_OP_JEQ_IMM:
      case EBPF_OP_JGT_REG:
      case EBPF_OP_JGT_IMM:
      case EBPF_OP_JGE_REG:
      case EBPF_OP_JGE_IMM:
      case EBPF_OP_JSET_REG:
      case EBPF_OP_JSET_IMM:
      case EBPF_OP_JNE_REG:
      case EBPF_OP_JNE_IMM:
      case EBPF_OP_JSGT_IMM:
      case EBPF_OP_JSGT_REG:
      case EBPF_OP_JSGE_IMM:
      case EBPF_OP_JSGE_REG:
          new_pc = i + 1 + inst.offset;
          if (insts[new_pc].opcode == 0) {
              *errmsg = ubpf_error("jump to middle of lddw at PC %d", i);
              return false;
          }
          break;

      case EBPF_OP_CALL:
          if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
              *errmsg = ubpf_error("invalid call immediate at PC %d", i);
              return false;
          }
          if (!vm->ext_funcs[inst.imm]) {
              *errmsg = ubpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
              return false;
          }
          break;

      case EBPF_OP_EXIT:
          break;

      case EBPF_OP_DIV_IMM:
      case EBPF_OP_MOD_IMM:
      case EBPF_OP_DIV64_IMM:
      case EBPF_OP_MOD64_IMM:
          if (inst.imm == 0) {
              *errmsg = ubpf_error("division by zero at PC %d", i);
              return false;
          }
          break;

      default:
          *errmsg = ubpf_error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
          return false;
      }

      if (inst.src > 10) {
          *errmsg = ubpf_error("invalid source register at PC %d", i);
          return false;
      }

      if (inst.dst > 9 && !(store && inst.dst == 10)) {
          *errmsg = ubpf_error("invalid destination register at PC %d", i);
          return false;
      }
  }

  return true;
}
