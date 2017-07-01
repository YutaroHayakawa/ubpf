# Copyright 2015 Big Switch Networks, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CFLAGS := -Wall -Werror -Iinc -O2 -g
LDLIBS := -lm

ifeq ($(COVERAGE),1)
CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-arcs
endif

ifeq ($(ASAN),1)
CFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
endif

all: libdbpf.a

dbpf_jit_x86_64.o: dbpf_jit_x86_64.c dbpf_jit_x86_64.h

libdbpf.a: dbpf_vm.o dbpf_jit_x86_64.o dbpf_loader.o
	ar rc $@ $^

clean:
	rm -f test libdbpf.a *.o
