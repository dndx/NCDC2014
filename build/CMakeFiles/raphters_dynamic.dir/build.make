# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/cdc/Desktop/webapp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/cdc/Desktop/webapp/bin

# Include any dependencies generated for this target.
include CMakeFiles/raphters_dynamic.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/raphters_dynamic.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/raphters_dynamic.dir/flags.make

CMakeFiles/raphters_dynamic.dir/dispatcher.c.o: CMakeFiles/raphters_dynamic.dir/flags.make
CMakeFiles/raphters_dynamic.dir/dispatcher.c.o: ../dispatcher.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/cdc/Desktop/webapp/bin/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/raphters_dynamic.dir/dispatcher.c.o"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/raphters_dynamic.dir/dispatcher.c.o   -c /home/cdc/Desktop/webapp/dispatcher.c

CMakeFiles/raphters_dynamic.dir/dispatcher.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/raphters_dynamic.dir/dispatcher.c.i"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/cdc/Desktop/webapp/dispatcher.c > CMakeFiles/raphters_dynamic.dir/dispatcher.c.i

CMakeFiles/raphters_dynamic.dir/dispatcher.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/raphters_dynamic.dir/dispatcher.c.s"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/cdc/Desktop/webapp/dispatcher.c -o CMakeFiles/raphters_dynamic.dir/dispatcher.c.s

CMakeFiles/raphters_dynamic.dir/dispatcher.c.o.requires:
.PHONY : CMakeFiles/raphters_dynamic.dir/dispatcher.c.o.requires

CMakeFiles/raphters_dynamic.dir/dispatcher.c.o.provides: CMakeFiles/raphters_dynamic.dir/dispatcher.c.o.requires
	$(MAKE) -f CMakeFiles/raphters_dynamic.dir/build.make CMakeFiles/raphters_dynamic.dir/dispatcher.c.o.provides.build
.PHONY : CMakeFiles/raphters_dynamic.dir/dispatcher.c.o.provides

CMakeFiles/raphters_dynamic.dir/dispatcher.c.o.provides.build: CMakeFiles/raphters_dynamic.dir/dispatcher.c.o

CMakeFiles/raphters_dynamic.dir/request.c.o: CMakeFiles/raphters_dynamic.dir/flags.make
CMakeFiles/raphters_dynamic.dir/request.c.o: ../request.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/cdc/Desktop/webapp/bin/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/raphters_dynamic.dir/request.c.o"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/raphters_dynamic.dir/request.c.o   -c /home/cdc/Desktop/webapp/request.c

CMakeFiles/raphters_dynamic.dir/request.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/raphters_dynamic.dir/request.c.i"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/cdc/Desktop/webapp/request.c > CMakeFiles/raphters_dynamic.dir/request.c.i

CMakeFiles/raphters_dynamic.dir/request.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/raphters_dynamic.dir/request.c.s"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/cdc/Desktop/webapp/request.c -o CMakeFiles/raphters_dynamic.dir/request.c.s

CMakeFiles/raphters_dynamic.dir/request.c.o.requires:
.PHONY : CMakeFiles/raphters_dynamic.dir/request.c.o.requires

CMakeFiles/raphters_dynamic.dir/request.c.o.provides: CMakeFiles/raphters_dynamic.dir/request.c.o.requires
	$(MAKE) -f CMakeFiles/raphters_dynamic.dir/build.make CMakeFiles/raphters_dynamic.dir/request.c.o.provides.build
.PHONY : CMakeFiles/raphters_dynamic.dir/request.c.o.provides

CMakeFiles/raphters_dynamic.dir/request.c.o.provides.build: CMakeFiles/raphters_dynamic.dir/request.c.o

CMakeFiles/raphters_dynamic.dir/response.c.o: CMakeFiles/raphters_dynamic.dir/flags.make
CMakeFiles/raphters_dynamic.dir/response.c.o: ../response.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/cdc/Desktop/webapp/bin/CMakeFiles $(CMAKE_PROGRESS_3)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/raphters_dynamic.dir/response.c.o"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/raphters_dynamic.dir/response.c.o   -c /home/cdc/Desktop/webapp/response.c

CMakeFiles/raphters_dynamic.dir/response.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/raphters_dynamic.dir/response.c.i"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/cdc/Desktop/webapp/response.c > CMakeFiles/raphters_dynamic.dir/response.c.i

CMakeFiles/raphters_dynamic.dir/response.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/raphters_dynamic.dir/response.c.s"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/cdc/Desktop/webapp/response.c -o CMakeFiles/raphters_dynamic.dir/response.c.s

CMakeFiles/raphters_dynamic.dir/response.c.o.requires:
.PHONY : CMakeFiles/raphters_dynamic.dir/response.c.o.requires

CMakeFiles/raphters_dynamic.dir/response.c.o.provides: CMakeFiles/raphters_dynamic.dir/response.c.o.requires
	$(MAKE) -f CMakeFiles/raphters_dynamic.dir/build.make CMakeFiles/raphters_dynamic.dir/response.c.o.provides.build
.PHONY : CMakeFiles/raphters_dynamic.dir/response.c.o.provides

CMakeFiles/raphters_dynamic.dir/response.c.o.provides.build: CMakeFiles/raphters_dynamic.dir/response.c.o

CMakeFiles/raphters_dynamic.dir/raphters.c.o: CMakeFiles/raphters_dynamic.dir/flags.make
CMakeFiles/raphters_dynamic.dir/raphters.c.o: ../raphters.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/cdc/Desktop/webapp/bin/CMakeFiles $(CMAKE_PROGRESS_4)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/raphters_dynamic.dir/raphters.c.o"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/raphters_dynamic.dir/raphters.c.o   -c /home/cdc/Desktop/webapp/raphters.c

CMakeFiles/raphters_dynamic.dir/raphters.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/raphters_dynamic.dir/raphters.c.i"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /home/cdc/Desktop/webapp/raphters.c > CMakeFiles/raphters_dynamic.dir/raphters.c.i

CMakeFiles/raphters_dynamic.dir/raphters.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/raphters_dynamic.dir/raphters.c.s"
	/usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /home/cdc/Desktop/webapp/raphters.c -o CMakeFiles/raphters_dynamic.dir/raphters.c.s

CMakeFiles/raphters_dynamic.dir/raphters.c.o.requires:
.PHONY : CMakeFiles/raphters_dynamic.dir/raphters.c.o.requires

CMakeFiles/raphters_dynamic.dir/raphters.c.o.provides: CMakeFiles/raphters_dynamic.dir/raphters.c.o.requires
	$(MAKE) -f CMakeFiles/raphters_dynamic.dir/build.make CMakeFiles/raphters_dynamic.dir/raphters.c.o.provides.build
.PHONY : CMakeFiles/raphters_dynamic.dir/raphters.c.o.provides

CMakeFiles/raphters_dynamic.dir/raphters.c.o.provides.build: CMakeFiles/raphters_dynamic.dir/raphters.c.o

# Object files for target raphters_dynamic
raphters_dynamic_OBJECTS = \
"CMakeFiles/raphters_dynamic.dir/dispatcher.c.o" \
"CMakeFiles/raphters_dynamic.dir/request.c.o" \
"CMakeFiles/raphters_dynamic.dir/response.c.o" \
"CMakeFiles/raphters_dynamic.dir/raphters.c.o"

# External object files for target raphters_dynamic
raphters_dynamic_EXTERNAL_OBJECTS =

libraphters_dynamic.so: CMakeFiles/raphters_dynamic.dir/dispatcher.c.o
libraphters_dynamic.so: CMakeFiles/raphters_dynamic.dir/request.c.o
libraphters_dynamic.so: CMakeFiles/raphters_dynamic.dir/response.c.o
libraphters_dynamic.so: CMakeFiles/raphters_dynamic.dir/raphters.c.o
libraphters_dynamic.so: CMakeFiles/raphters_dynamic.dir/build.make
libraphters_dynamic.so: CMakeFiles/raphters_dynamic.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C shared library libraphters_dynamic.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/raphters_dynamic.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/raphters_dynamic.dir/build: libraphters_dynamic.so
.PHONY : CMakeFiles/raphters_dynamic.dir/build

CMakeFiles/raphters_dynamic.dir/requires: CMakeFiles/raphters_dynamic.dir/dispatcher.c.o.requires
CMakeFiles/raphters_dynamic.dir/requires: CMakeFiles/raphters_dynamic.dir/request.c.o.requires
CMakeFiles/raphters_dynamic.dir/requires: CMakeFiles/raphters_dynamic.dir/response.c.o.requires
CMakeFiles/raphters_dynamic.dir/requires: CMakeFiles/raphters_dynamic.dir/raphters.c.o.requires
.PHONY : CMakeFiles/raphters_dynamic.dir/requires

CMakeFiles/raphters_dynamic.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/raphters_dynamic.dir/cmake_clean.cmake
.PHONY : CMakeFiles/raphters_dynamic.dir/clean

CMakeFiles/raphters_dynamic.dir/depend:
	cd /home/cdc/Desktop/webapp/bin && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/cdc/Desktop/webapp /home/cdc/Desktop/webapp /home/cdc/Desktop/webapp/bin /home/cdc/Desktop/webapp/bin /home/cdc/Desktop/webapp/bin/CMakeFiles/raphters_dynamic.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/raphters_dynamic.dir/depend
