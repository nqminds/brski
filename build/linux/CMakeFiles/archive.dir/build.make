# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/alexandru/projects/brski

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/alexandru/projects/brski/build/linux

# Utility rule file for archive.

# Include any custom commands dependencies for this target.
include CMakeFiles/archive.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/archive.dir/progress.make

CMakeFiles/archive:
	/usr/bin/cmake -E tar cvz brski-x86_64-0.1.0-alpha.0.tar.gz --format=gnutar /usr/local

archive: CMakeFiles/archive
archive: CMakeFiles/archive.dir/build.make
.PHONY : archive

# Rule to build all files generated by this target.
CMakeFiles/archive.dir/build: archive
.PHONY : CMakeFiles/archive.dir/build

CMakeFiles/archive.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/archive.dir/cmake_clean.cmake
.PHONY : CMakeFiles/archive.dir/clean

CMakeFiles/archive.dir/depend:
	cd /home/alexandru/projects/brski/build/linux && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/alexandru/projects/brski /home/alexandru/projects/brski /home/alexandru/projects/brski/build/linux /home/alexandru/projects/brski/build/linux /home/alexandru/projects/brski/build/linux/CMakeFiles/archive.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/archive.dir/depend

