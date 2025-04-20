package antidebugseeker;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Manages the configuration for the AntiDebugSeeker plugin, loading rules
 * from .config files and descriptions from .json files.
 */
public class AntiDebugConfig {

    // --- Constants for Configuration Sections/Keys ---
    private static final String SECTION_API = "### Anti_Debug_API ###";
    private static final String SECTION_TECHNIQUE = "### Anti_Debug_Technique ###";
    private static final String SECTION_INSTRUCTION = "### Instructions ###"; // Example
    private static final String SECTION_BYTES = "### Byte_Sequences ###";   // Example
    private static final String KEY_DEFAULT_SEARCH_RANGE = "default_search_range=";
    private static final String KEY_SEARCH_RANGE = "search_range=";
    private static final String KEY_ENABLE_API_ANALYSIS = "enable_api_analysis=";
    private static final String KEY_ENABLE_KEYWORD_ANALYSIS = "enable_keyword_analysis=";
    private static final String KEY_ENABLE_INSTRUCTION_ANALYSIS = "enable_instruction_analysis=";
    private static final String KEY_ENABLE_BYTE_ANALYSIS = "enable_byte_analysis=";
    private static final String KEY_ENABLE_CSV_OUTPUT = "enable_csv_output=";
    private static final String KEY_CSV_OUTPUT_PATH = "csv_output_path=";

    // --- Configuration Data ---
    private final Map<String, String> apiCategories = new HashMap<>();
    private final Map<String, String> ruleDescriptions = new HashMap<>(); // Combined descriptions map
    private final List<KeywordGroup> keywordGroups = new ArrayList<>();
    private final List<String> apiCalls = new ArrayList<>();
    private final List<String> instructions = new ArrayList<>(); // Basic instruction list
    private final List<String> byteSequences = new ArrayList<>(); // Basic byte sequence list
    private int defaultSearchRange = 80;

    // --- New Feature Flags/Settings ---
    private boolean analyzeApiCallsEnabled = true;
    private boolean analyzeKeywordsEnabled = true;
    private boolean analyzeInstructionsEnabled = false; // Default off unless explicitly defined/enabled
    private boolean analyzeBytesEnabled = false;      // Default off unless explicitly defined/enabled
    private boolean csvOutputEnabled = false;
    private Path csvOutputPath = null; // Default to null, set from config

    /** Private constructor to force use of {@link #loadConfig()}. */
    private AntiDebugConfig() {}

    // --- Getters ---
    public List<String> getApiCalls() { return Collections.unmodifiableList(apiCalls); }
    public List<String> getInstructions() { return Collections.unmodifiableList(instructions); }
    public List<String> getByteSequences() { return Collections.unmodifiableList(byteSequences); }
    public List<KeywordGroup> getKeywordGroups() { return Collections.unmodifiableList(keywordGroups); }
    public String getApiCategory(String apiName) { return apiCategories.getOrDefault(apiName, "Unknown Category"); }
    public String getRuleDescription(String ruleName) { return ruleDescriptions.getOrDefault(ruleName, "No description available."); }
    public int getDefaultSearchRange() { return defaultSearchRange; }

    // New Feature Getters
    public boolean isAnalyzeApiCallsEnabled() { return analyzeApiCallsEnabled; }
    public boolean isAnalyzeKeywordsEnabled() { return analyzeKeywordsEnabled; }
    public boolean isAnalyzeInstructionsEnabled() { return analyzeInstructionsEnabled; }
    public boolean isAnalyzeBytesEnabled() { return analyzeBytesEnabled; }
    public boolean isCsvOutputEnabled() { return csvOutputEnabled; }
    public Path getCsvOutputPath() { return csvOutputPath; }

    // --- Loading Logic ---

    /**
     * Loads the configuration from default file locations within the Ghidra module data directory.
     * Assumes config file: data/anti_debug_Ghidra.config
     * Assumes JSON file: data/anti_debug_techniques_descriptions_Ghidra.json
     *
     * @return A loaded AntiDebugConfig instance.
     * @throws IOException If file reading fails.
     * @throws NotFoundException If the module data directory or config files cannot be found.
     */
    public static AntiDebugConfig loadConfig() throws IOException, NotFoundException {
        AntiDebugConfig config = new AntiDebugConfig();

        // --- Find and Load JSON Descriptions ---
        File jsonFile = Application.getModuleDataFile("AntiDebugSeeker", "data/anti_debug_techniques_descriptions_Ghidra.json").getFile(false);
        if (!jsonFile.exists() || !jsonFile.isFile()) {
            throw new IOException("JSON description file not found or is not a file: " + jsonFile.getAbsolutePath());
        }
        String jsonContent = Files.readString(jsonFile.toPath());
        config.parseJsonDescriptions(jsonContent);
        Msg.info(AntiDebugConfig.class, "Loaded " + config.ruleDescriptions.size() + " descriptions from JSON.");

        // --- Find and Load Config Rules ---
        File configFile = Application.getModuleDataFile("AntiDebugSeeker", "data/anti_debug_Ghidra.config").getFile(false);
         if (!configFile.exists() || !configFile.isFile()) {
            throw new IOException("Config rule file not found or is not a file: " + configFile.getAbsolutePath());
        }
        config.parseConfigFile(configFile.getAbsolutePath());
        Msg.info(AntiDebugConfig.class, "Loaded " + config.apiCalls.size() + " API rules.");
        Msg.info(AntiDebugConfig.class, "Loaded " + config.keywordGroups.size() + " Keyword Group rules.");
        Msg.info(AntiDebugConfig.class, "Loaded " + config.instructions.size() + " Instruction rules.");
        Msg.info(AntiDebugConfig.class, "Loaded " + config.byteSequences.size() + " Byte Sequence rules.");

        return config;
    }

    /** Parses the JSON string containing rule descriptions. */
    private void parseJsonDescriptions(String jsonString) {
        Gson gson = new Gson();
        try {
            Type type = new TypeToken<Map<String, String>>(){}.getType();
            Map<String, String> loadedDescriptions = gson.fromJson(jsonString, type);

            if (loadedDescriptions != null) {
                loadedDescriptions.forEach((key, value) -> {
                    if (key != null && value != null) {
                        String cleanedValue = value.replace("\\n", "\n").replace("\\\"", "\"");
                        if (cleanedValue.endsWith(".")) {
                            cleanedValue = cleanedValue.substring(0, cleanedValue.length() - 1);
                        }
                        this.ruleDescriptions.put(key.trim(), cleanedValue.trim());
                    }
                });
            }
        } catch (JsonSyntaxException e) {
            Msg.error(this, "Failed to parse JSON descriptions: " + e.getMessage(), e);
            // Continue without descriptions or throw? For now, log error and continue.
        }
    }

    /** Parses the .config file containing analysis rules and settings. */
    private void parseConfigFile(String filePath) throws IOException {
        String line;
        int lineNumber = 0;
        String currentSection = "";
        String currentRuleName = "";
        List<String> currentKeywords = new ArrayList<>();
        int currentSearchRange = -1; // Use -1 to indicate rule-specific range not set yet
        String currentCategory = "";

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("//") || line.startsWith("# ")) { // Skip comments and empty lines
                    continue;
                }

                // --- Global Settings ---
                if (line.toLowerCase().startsWith(KEY_DEFAULT_SEARCH_RANGE)) {
                    parseIntegerSetting(line, KEY_DEFAULT_SEARCH_RANGE, lineNumber, val -> this.defaultSearchRange = val);
                    continue;
                }
                if (line.toLowerCase().startsWith(KEY_ENABLE_API_ANALYSIS)) {
                    parseBooleanSetting(line, KEY_ENABLE_API_ANALYSIS, lineNumber, val -> this.analyzeApiCallsEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_ENABLE_KEYWORD_ANALYSIS)) {
                    parseBooleanSetting(line, KEY_ENABLE_KEYWORD_ANALYSIS, lineNumber, val -> this.analyzeKeywordsEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_ENABLE_INSTRUCTION_ANALYSIS)) {
                    parseBooleanSetting(line, KEY_ENABLE_INSTRUCTION_ANALYSIS, lineNumber, val -> this.analyzeInstructionsEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_ENABLE_BYTE_ANALYSIS)) {
                    parseBooleanSetting(line, KEY_ENABLE_BYTE_ANALYSIS, lineNumber, val -> this.analyzeBytesEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_ENABLE_CSV_OUTPUT)) {
                    parseBooleanSetting(line, KEY_ENABLE_CSV_OUTPUT, lineNumber, val -> this.csvOutputEnabled = val);
                    continue;
                }
                 if (line.toLowerCase().startsWith(KEY_CSV_OUTPUT_PATH)) {
                    parsePathSetting(line, KEY_CSV_OUTPUT_PATH, lineNumber, val -> this.csvOutputPath = val);
                    continue;
                }

                // --- Section Handling ---
                if (line.startsWith("###")) {
                    // Finalize previous keyword group if ending that section
                    finalizeKeywordGroup(currentSection, currentRuleName, currentKeywords, currentSearchRange);

                    currentSection = line; // Store the full section header
                    currentRuleName = "";
                    currentKeywords.clear();
                    currentCategory = "";
                    currentSearchRange = -1; // Reset rule-specific range

                    Msg.debug(this, "Entering section: " + currentSection);
                    continue; // Move to next line after processing section header
                }

                // --- Section-Specific Parsing ---
                switch (currentSection) {
                    case SECTION_API:
                        if (line.startsWith("[")) {
                            currentCategory = line.substring(1, line.length() - 1).trim();
                        } else {
                            String apiName = line;
                            apiCalls.add(apiName);
                            apiCategories.put(apiName, currentCategory.isEmpty() ? "Default" : currentCategory);
                        }
                        break;

                    case SECTION_TECHNIQUE:
                        if (line.startsWith("[")) {
                            // Finalize previous keyword group before starting new one
                            finalizeKeywordGroup(currentSection, currentRuleName, currentKeywords, currentSearchRange);

                            currentRuleName = line.substring(1, line.length() - 1).trim();
                            currentSearchRange = -1; // Reset rule-specific range
                            currentKeywords.clear(); // Clear for the new rule
                        } else if (line.toLowerCase().startsWith(KEY_SEARCH_RANGE)) {
                            parseIntegerSetting(line, KEY_SEARCH_RANGE, lineNumber, val -> currentSearchRange = val);
                        } else if (!currentRuleName.isEmpty()) { // Ensure we are inside a rule definition [RuleName]
                            currentKeywords.add(line);
                        } else {
                             Msg.warn(this, "Config Parse Warning (Line " + lineNumber + "): Keyword '" + line + "' found outside a rule definition [RuleName] in " + SECTION_TECHNIQUE);
                        }
                        break;

                    case SECTION_INSTRUCTION:
                        // Add parsing logic for instruction patterns if needed
                        instructions.add(line);
                        break;

                    case SECTION_BYTES:
                        // Add parsing logic for byte sequences if needed
                        byteSequences.add(line);
                        break;

                    default:
                        // Line outside known section or before first section
                        if (!currentSection.isEmpty()) { // Only warn if we thought we were in a section
                           Msg.warn(this, "Config Parse Warning (Line " + lineNumber + "): Unexpected line '" + line + "' in section '" + currentSection + "'");
                        }
                        break;
                }
            }

            // Finalize the last keyword group if the file ends within that section
            finalizeKeywordGroup(currentSection, currentRuleName, currentKeywords, currentSearchRange);

        } // try-with-resources ensures reader is closed
    }

    /** Helper to finalize adding a KeywordGroup. */
    private void finalizeKeywordGroup(String currentSection, String ruleName, List<String> keywords, int searchRange) {
        if (SECTION_TECHNIQUE.equals(currentSection) && !ruleName.isEmpty() && !keywords.isEmpty()) {
            int rangeToUse = (searchRange >= 0) ? searchRange : this.defaultSearchRange;
            String description = ruleDescriptions.getOrDefault(ruleName, "No description provided.");
            keywordGroups.add(new KeywordGroup(ruleName, new ArrayList<>(keywords), rangeToUse, description));
             Msg.debug(this,"Finalized keyword group: " + ruleName + " with " + keywords.size() + " keywords, range " + rangeToUse);
        }
    }

    /** Helper to parse boolean settings. */
    private void parseBooleanSetting(String line, String key, int lineNumber, java.util.function.Consumer<Boolean> setter) {
        String value = line.substring(key.length()).trim().toLowerCase();
        if (value.equals("true")) {
            setter.accept(true);
        } else if (value.equals("false")) {
            setter.accept(false);
        } else {
            Msg.warn(this, "Config Parse Warning (Line " + lineNumber + "): Invalid boolean value for " + key + ": '" + value + "'. Using default.");
        }
    }

    /** Helper to parse integer settings. */
    private void parseIntegerSetting(String line, String key, int lineNumber, java.util.function.IntConsumer setter) {
        String value = line.substring(key.length()).trim();
        try {
            setter.accept(Integer.parseInt(value));
        } catch (NumberFormatException e) {
             Msg.warn(this, "Config Parse Warning (Line " + lineNumber + "): Invalid integer value for " + key + ": '" + value + "'. Using default.");
        }
    }

     /** Helper to parse path settings. */
    private void parsePathSetting(String line, String key, int lineNumber, java.util.function.Consumer<Path> setter) {
        String value = line.substring(key.length()).trim();
        try {
            // Consider resolving relative paths against Ghidra project or user home?
            // For simplicity, treat as absolute or relative to CWD for now.
            Path path = Paths.get(value);
            setter.accept(path);
        } catch (InvalidPathException e) {
             Msg.warn(this, "Config Parse Warning (Line " + lineNumber + "): Invalid path for " + key + ": '" + value + "'. Setting ignored.", e);
        }
    }


    // --- Inner Class for Keyword Groups ---
    /** Represents a group of keywords defining an anti-debug technique pattern. */
    public static class KeywordGroup {
        private final String name;
        private final List<String> keywords;
        private final int searchRange;
        private final String description;

        public KeywordGroup(String name, List<String> keywords, int searchRange, String description) {
            this.name = Objects.requireNonNull(name, "KeywordGroup name cannot be null");
            this.keywords = Collections.unmodifiableList(new ArrayList<>(Objects.requireNonNull(keywords, "Keyword list cannot be null")));
            this.searchRange = searchRange;
            this.description = Objects.requireNonNull(description, "Description cannot be null");
            if (this.keywords.isEmpty()) {
                throw new IllegalArgumentException("KeywordGroup must contain at least one keyword: " + name);
            }
        }

        // --- Getters ---
        public String getName() { return name; }
        public List<String> getKeywords() { return keywords; }
        public int getSearchRange() { return searchRange; }
        public String getDescription() { return description; }

        // --- Helper Methods ---
        public String getPrimaryKeyword() {
            return keywords.get(0); // Assumes list is not empty (checked in constructor)
        }

        public List<String> getSecondaryKeywords() {
            return keywords.size() > 1 ? keywords.subList(1, keywords.size()) : Collections.emptyList();
        }

        public String getKeywordByIndex(int index) {
            return (index >= 0 && index < keywords.size()) ? keywords.get(index) : null;
        }

        @Override
        public String toString() {
            return "KeywordGroup{" +
                   "name='" + name + '\'' +
                   ", keywords=" + keywords +
                   ", searchRange=" + searchRange +
                   '}';
        }
    }
}
