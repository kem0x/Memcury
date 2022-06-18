# memcury.h

A simple one header solution for memory manipulation in C++.

## Usage

Just `#include "memcury.h"` in your code!.

Check [example](/example.cpp) for code examples.

The current supported platform is Windows only, no plans for supporting more platforms.

This project was intented to be used internaly (from a dynamic link library).

## The pitch

- Containers:

  - PE::Address: A pointer container.
  - PE::Section: Portable executable section container for internal usage.

- Modules:

  - Scanner:

    - Constructors:

      - Default: Takes a pointer to start the scanning from.
      - FindPattern: Finds a pattern in memory.
      - FindStringRef: Finds a string reference in memory, supports all types of strings.

    - Functions:
      - SetTargetModule: Sets the target module for the scanner.
      - ScanFor: Scans for a byte(s) near the current address.
      - FindFunctionBoundary: Finds the boundary of a function near the current address.
      - RelativeOffset: Gets the relative offset of the current address.
      - AbsoluteOffset: Gets the absolute offset of the current address.
      - GetAs: Gets the current address as a type.
      - Get: Gets the current address as an int64.

  - TrampolineHook:

    - Constructors:
      - Default: Takes a pointer pointer to the target function and a pointer to the hook function.
    - Functions:
      - Commit: Commits the hook.
      - Revert: Reverts the hook.
      - Toggle: Toggles the hook on\off.

  - VEHHook:
    - Functions:
      - Init: Initializes the VEH Hook system.
      - AddHook: Adds a hook to the VEH Hook system.
      - RemoveHook: Removes a hook from the VEH Hook system.
