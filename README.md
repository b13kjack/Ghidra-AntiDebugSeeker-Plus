# Ghidra AntiDebugSeeker Plus (WIP)

**A Ghidra script and plugin for identifying anti-debugging techniques in malware.**

This tool is a complete refactor of the original [AntiDebugSeeker IDA Plugin](https://github.com/LAC-Japan/IDA_Plugin_AntiDebugSeeker) by LAC, adapted and enhanced for Ghidra. It helps analysts automatically extract potential anti-debugging methods used by malware, making analysis more efficient.

It can be used in two ways:
1.  As a standalone **Ghidra Script** (`.java`).
2.  As an integrated **Ghidra Module Extension** (Plugin).

<p align="center">
  <img src="pictures/Ghidra_AntiDebugSeeker.gif" alt="Ghidra AntiDebugSeeker Plus Demo" width="600"/>
</p>

## Key Features

* **API Detection:** Extracts potential anti-debugging Windows API calls used by the malware.
* **Technique Detection:** Identifies anti-debugging techniques based on configurable keyword sequences, catching methods not solely identifiable by API calls.
* **Customizable Rules:** Easily add or modify detection rules (APIs and keyword techniques) via configuration files.
* **Clear Results:** Presents findings clearly through console output, bookmarks, and optional GUI elements (extension mode).
* **Code Annotation:** Marks detected locations directly in the disassembly view with colors and comments.

*Note: For packed malware, running this tool after unpacking and fixing the Import Address Table (IAT) yields better results.*

## Requirements

* **Ghidra:** Version 11.0.1 or compatible.

## Core Files

You'll need the following files depending on your usage method:

<<<<<<< HEAD

## Understanding the Provided Rule Files (`rule_files` directory)

The `rule_files` directory in this repository contains example rule definition (`.config`) and description (`.json`) files. You may find different versions or sets of these files in subdirectories like:

*   `rule_files/config/` and `rule_files/json/`
*   `rule_files/20241021_UPDATE/`

When the script or plugin prompts you to "Select the Configuration File" and "Select the JSON Description File", you should navigate to the `rule_files` directory (or wherever you have stored your desired rule files) and choose the specific `.config` and `.json` files you wish to use for the analysis. You can use the provided files as a starting point or create your own custom versions.

## anti_debug_Ghidra.config and anti_debug_techniques_descriptions_Ghidra.json 
=======
1.  **Usage Mode Files:**
    * **Script:** `AntiDebugSeeker.java`
    * **Extension:** `ghidra_11.0.1_AntiDebugSeeker.zip` (Contains the compiled plugin)
2.  **Configuration File:**
    * `anti_debug_Ghidra.config` - Defines the detection rules (APIs and techniques).
3.  **Description File:**
    * `anti_debug_techniques_descriptions_Ghidra.json` - Contains descriptions for technique-based rules, shown in comments.
>>>>>>> f08b85678568836945d54d84892f993eea4e807d

## Configuration Files

These files allow you to customize the detection logic:

### `anti_debug_Ghidra.config`

This file contains two main sections: `[Anti_Debug_API]` and `[Anti_Debug_Technique]`.

* **`[Anti_Debug_API]` Section:**
    * Define categories and list Windows API names to detect.
    * Detection uses **exact matching**.
    <p align="center">
      <img src="pictures/HowToWriteAnti_Debug_API_Section.png" alt="Anti_Debug_API Section Example" width="380"/>
    </p>

* **`[Anti_Debug_Technique]` Section:**
    * Define rules using sequences of one to three keywords.
    * Detection uses **partial matching** within a defined search range.
    * **Search Flow:**
        1.  Find the first keyword.
        2.  If found, search for the second keyword within a specified range (default: `80` bytes).
        3.  If found, search for the third keyword within the range relative to the second keyword.
    <p align="center">
      <img src="pictures/HowToWriteAnti_Debug_Technique_Section.png" alt="Anti_Debug_Technique Section Example" width="430"/>
    </p>
    * **Custom Search Range:** To override the default range for a specific rule, append `search_range=<value>` to a keyword line.
    <p align="center">
      <img src="pictures/Custom_SearchRange.png" alt="Custom Search Range Example" width="380"/>
    </p>

### `anti_debug_techniques_descriptions_Ghidra.json`

* Provides descriptive text for rules defined in the `[Anti_Debug_Technique]` section of the `.config` file.
* These descriptions appear as POST comments in the Ghidra disassembly view for detected techniques.
<p align="center">
  <img src="pictures/anti_debug_techniques_descriptions.png" alt="Technique Descriptions JSON Example" width="600"/>
</p>

## Installation and Usage

Choose the method that suits your workflow:

### Method 1: Using as a Ghidra Script

1.  **Placement:** Place `AntiDebugSeeker.java`, `anti_debug_Ghidra.config`, and `anti_debug_techniques_descriptions_Ghidra.json` in your Ghidra scripts directory.
2.  **Execution:**
    * Open Ghidra's `Script Manager`.
    * Navigate to and select `AntiDebugSeeker.java`.
    * Click the "Run Script" button (green play icon).
    * You will be prompted twice:
        * First, select your `anti_debug_Ghidra.config` file.
        * Second, select your `anti_debug_techniques_descriptions_Ghidra.json` file.
3.  **Results:** View detection results in the `Console - Scripting` window and via `Bookmarks`.

### Method 2: Using as a Ghidra Extension (Plugin)

1.  **Installation:**
    * In Ghidra, go to `File` -> `Install Extensions...`.
    * Click the green `+` icon ("Add extension").
    * Navigate to and select the `ghidra_11.0.1_AntiDebugSeeker.zip` file.
    * Ensure the `AntiDebugSeeker` extension is checked in the list.
    * Click `OK`. You will need to restart Ghidra.
2.  **Execution:**
    * Once Ghidra restarts and your project is open, go to `Window` -> `AntiDebugSeekerPlugin`. This opens the plugin's GUI panel.
    <p align="center"><img src="pictures/How_to_setup_and_Execute_module_3.png" alt="Accessing the Plugin Window" ></p>
    * Click the `Start Analyze` button in the plugin panel.
    <p align="center"><img src="pictures/How_to_setup_and_Execute_module_4.png" alt="Plugin Panel - Start Analyze" ></p>
    * You will be prompted twice (similar to the script method):
        * Select your `anti_debug_Ghidra.config` file.
        * Select your `anti_debug_techniques_descriptions_Ghidra.json` file.
    <p align="center"><img src="pictures/How_to_setup_and_Execute_module_5.png" alt="File Selection Prompt" ></p>
    * A progress bar (with a dragon!) will appear. Wait for the "Analysis Complete" message.
    <p align="center"><img src="pictures/How_to_setup_and_Execute_module_6.png" alt="Analysis Progress and Completion" ></p>
3.  **Results:** View detection results in the plugin panel's `Text Area`, via `Bookmarks`, and through annotations in the disassembly view.

## Understanding the Results

Both methods provide results in several ways:

* **Console / Text Area:**
    * **Script:** Results are printed to the `Console - Scripting` window.
    * **Extension:** Results appear in the plugin panel's `Text Area`.
        * **`Display only the detection results` Button:** Filters the output to show only the lines where detections occurred.
        <p align="center"><img src="pictures/Verifing_the_results_1.png" alt="GUI - Display Only Detections" ></p>
        * **`Detected Function List` Button:** Groups the detected results by the function in which they were found, helping prioritize analysis.
        <p align="center"><img src="pictures/Verifing_the_results_2.png" alt="GUI - Detected Function List" ></p>

* **Bookmarks:**
    * Detected APIs are bookmarked under the `Potential of Anti Debug API` category.
    * Detected techniques are bookmarked under the `Anti Debug Technique` category.
    <p align="center"><img src="pictures/Verifing_the_results_3.png" alt="Bookmarks View" ></p>

* **Disassembly View Annotations:**
    * **API Detections:** Background color is set to **green**. The rule name (API category) is added as a `PRE comment`.
    <p align="center"><img src="pictures/Detected_Keywords_1.png" alt="API Detection Annotation" ></p>
    * **Technique Detections:** Background color is set to **orange**. The rule name is added as a `PRE comment`. The description from the `.json` file is added as a `POST comment`.
    <p align="center"><img src="pictures/Detected_Keywords_2.png" alt="Technique Detection Annotation" ></p>

## List of Detectable Techniques (Default Rules)

The default `anti_debug_Ghidra.config` includes rules for the following techniques (defined in `[Anti_Debug_Technique]`):
