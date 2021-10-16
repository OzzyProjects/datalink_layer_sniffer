SRC := src
# headers folder (*.h)
INC := headers
#  main.c (your main c source code)
MAIN := main.c
# name of the generated executable
EXEC := raw_sock

# the main file can be alone or within the sources folder
ifneq ("$(wildcard $(MAIN))","")
	sources := $(MAIN) $(wildcard $(SRC)/*.c)
else
	sources := $(wildcard $(SRC)/*.c)
endif

# objects files list
objects := $(sources:.c=.o)
# dependacies files list
deps    := $(objects:.o=.d)
# compilator's choice
CC := gcc
CPPFLAGS := -I $(INC)
# compilator's options (you may add some options here)
CFLAGS := -g -Wall -Wextra -pedantic

LDFLAGS=-lm

# linking
$(EXEC) : $(objects)
	$(CC) $(LDFLAGS) $^ -o $@ -lpcap -lpthread
	$(RM) $(objects) $(deps)
	 @echo "Compilation done !"

# compilation from source files
$(SRC)/%.o: $(SRC)/%.c
	$(CC) $(CPPFLAGS) -c $^ -o $@

# subroutine to remove exec
.PHONY: clean allclean
clean:
	$(RM) $(EXEC)

allclean:
	$(RM) $(objects) $(deps)
	
# dependancies between files
-include $(deps)
