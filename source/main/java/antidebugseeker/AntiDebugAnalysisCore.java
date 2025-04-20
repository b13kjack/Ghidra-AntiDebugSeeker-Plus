package antidebugseeker;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.NumericUtilities;
import ghidra.framework.plugintool.ServiceProvider;
import java.awt.Color;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.FunctionIterator;
import antidebugseeker.CsvResultWriter; // Import CsvResultWriter
import antidebugseeker.AntiDebugConfig.InstructionRule; // Import inner class
import antidebugseeker.AntiDebugConfig.InstructionStep; // Import inner class
import antidebugseeker.AntiDebugConfig.OperandCheck; // Import inner class

// --- End Imports ---

/**
 * Core analysis engine for the AntiDebugSeeker plugin.
 * Performs searches for API calls, keyword patterns, instructions, and byte sequences.
 * Extended version includes API label reference search and keyword cross-reference checks.
 */
public class AntiDebugAnalysisCore {

    // --- Constants ---
    private static final Color API_COLOR = new Color(173, 255, 47, 128); // Light green (semi-transparent)
    private static final Color API_LABEL_COLOR = new Color(144, 238, 144, 128); // Lighter green for API Label Refs
    private static final Color PATTERN_PRIMARY_COLOR = new Color(255, 165, 0, 128); // Orange (semi-transparent)
    private static final Color PATTERN_SECONDARY_COLOR = new Color(255, 200, 120, 128); // Lighter orange (semi-transparent)
    private static final Color INSTRUCTION_COLOR = new Color(255, 105, 180, 128); // Hot pink (semi-transparent)
    private static final Color BYTES_COLOR = new Color(135, 206, 250, 128); // Light sky blue (semi-transparent)

    private static final String BOOKMARK_CATEGORY_API = "AntiDebug API";
    private static final String BOOKMARK_CATEGORY_API_LABEL = "AntiDebug API Label Ref"; // New category
    private static final String BOOKMARK_CATEGORY_PATTERN = "AntiDebug Pattern";
    private static final String BOOKMARK_CATEGORY_PATTERN_XREF = "AntiDebug Pattern (XRef)"; // New category
    private static final String BOOKMARK_CATEGORY_PATTERN_PART = "Pattern Part";
    private static final String BOOKMARK_CATEGORY_INSTRUCTION = "AntiDebug Instruction";
    private static final String BOOKMARK_CATEGORY_BYTES = "AntiDebug Bytes";

    /** Private constructor to prevent instantiation. */
    private AntiDebugAnalysisCore() {}

    /** Represents the severity level of a finding. */
    public enum Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

    /** Represents a single finding during analysis. */
    public record Finding(
        Address address,
        String type, // e.g., "API", "API Label Ref", "Keyword Group", "Keyword Group (XRef)", "Instruction Sequence", "Bytes"
        String ruleName, // Name of the rule/API/keyword group/byte sequence that triggered the finding
        Severity severity,
        String description, // Detailed description from JSON or generated
        String functionContext // Name of the containing function, or "N/A"
    ) {
        /** Creates a Finding, ensuring non-null values where appropriate. */
        public Finding {
            Objects.requireNonNull(address, "Finding address cannot be null");
            Objects.requireNonNull(type, "Finding type cannot be null");
            Objects.requireNonNull(ruleName, "Finding ruleName cannot be null");
            Objects.requireNonNull(severity, "Finding severity cannot be null");
            description = (description != null) ? description : ""; // Allow empty description
            functionContext = (functionContext != null && !functionContext.isBlank()) ? functionContext : "N/A";
        }
    }

    /**
     * Analyzes the given program based on the provided configuration.
     *
     * @param program The program to analyze.
     * @param config The analysis configuration.
     * @param logger A consumer for logging messages (e.g., to the GUI).
     * @param monitor A task monitor for progress updates and cancellation checks.
     * @throws CancelledException If the analysis is cancelled by the user.
     */
    public static void analyzeProgram(Program program, AntiDebugConfig config, Consumer<String> logger, TaskMonitor monitor) throws CancelledException {
        logger.accept("Starting Anti-Debug Analysis...\n");
        List<Finding> findings = new ArrayList<>(); // Store all findings

        // --- Perform Enabled Analyses ---
        if (config.isAnalyzeApiCallsEnabled()) {
            monitor.setMessage("Analyzing API Calls & Labels..."); // Updated message
            analyzeApiCalls(program, config, logger, monitor, findings);
            monitor.checkCancelled();
        } else {
            logger.accept("Skipping API Call/Label analysis (disabled in config).\n");
        }

        if (config.isAnalyzeKeywordsEnabled()) {
            monitor.setMessage("Analyzing Keyword Patterns (Direct & XRef)..."); // Updated message
            analyzeKeywordPatterns(program, config, logger, monitor, findings);
            monitor.checkCancelled();
        } else {
            logger.accept("Skipping Keyword Pattern analysis (disabled in config).\n");
        }

        if (config.isAnalyzeInstructionsEnabled()) {
            monitor.setMessage("Analyzing Instructions...");
            analyzeInstructions(program, config, logger, monitor, findings);
            monitor.checkCancelled();
        } else {
            logger.accept("Skipping Instruction analysis (disabled in config).\n");
        }

        if (config.isAnalyzeBytesEnabled()) {
            monitor.setMessage("Analyzing Byte Sequences...");
            analyzeBytes(program, config, logger, monitor, findings);
            monitor.checkCancelled();
        } else {
             logger.accept("Skipping Byte Sequence analysis (disabled in config).\n");
        }

        // --- Finalize and Report ---
        logger.accept("\nAnalysis Complete.\n");
        logger.accept("--- Summary ---\n");
        logger.accept(String.format(" - API Rules Searched: %d (%s)\n", config.getApiCalls().size(), config.isAnalyzeApiCallsEnabled() ? "Enabled" : "Disabled"));
        logger.accept(String.format(" - Keyword Groups Searched: %d (%s)\n", config.getKeywordGroups().size(), config.isAnalyzeKeywordsEnabled() ? "Enabled" : "Disabled"));
        logger.accept(String.format(" - Instruction Rules Searched: %d (%s)\n", config.getInstructionRules().size(), config.isAnalyzeInstructionsEnabled() ? "Enabled" : "Disabled"));
        logger.accept(String.format(" - Byte Sequences Searched: %d (%s)\n", config.getByteSequences().size(), config.isAnalyzeBytesEnabled() ? "Enabled" : "Disabled"));
        logger.accept("Total Findings: " + findings.size() + "\n");
        logger.accept("See details above and Bookmarks panel for findings.\n");

        // --- CSV Output ---
        if (config.isCsvOutputEnabled()) {
            monitor.setMessage("Writing results to CSV...");
            Path outputPath = config.getCsvOutputPath();
            if (outputPath != null) {
                try {
                    CsvResultWriter.writeResults(outputPath, findings);
                    logger.accept("Results successfully written to: " + outputPath + "\n");
                } catch (IOException e) {
                    logger.accept("Error writing CSV results: " + e.getMessage() + "\n");
                    Msg.error(AntiDebugAnalysisCore.class, "Failed to write CSV results to " + outputPath, e);
                }
            } else {
                logger.accept("CSV output enabled, but no output path specified in config.\n");
                Msg.warn(AntiDebugAnalysisCore.class, "CSV output enabled but csv_output_path is not set in config.");
            }
        }
    }

    // =====================================================================================
    // Analysis Methods
    // =====================================================================================

    /** Analyzes API calls, function calls, and label references based on the configuration. */
    private static void analyzeApiCalls(Program program, AntiDebugConfig config, Consumer<String> logger, TaskMonitor monitor, List<Finding> findings) throws CancelledException {
        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager referenceManager = program.getReferenceManager();
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        Listing listing = program.getListing();

        logger.accept("\n--- Searching for API Calls, Functions & Label References ---\n");
        int apiFoundCount = 0;
        Set<Address> reportedReferenceAddresses = new HashSet<>(); // Avoid duplicate reports for same location

        for (String apiName : config.getApiCalls()) {
            monitor.checkCancelled();
            monitor.setMessage("API/Label: " + apiName);
            boolean foundAnyRefForThisApi = false;

            // --- Search External Symbols (Imports) ---
            SymbolIterator externalSymbols = symbolTable.getExternalSymbolIterator(apiName);
            while (externalSymbols.hasNext()) {
                 monitor.checkCancelled();
                 Symbol extSym = externalSymbols.next();
                 ReferenceIterator refIter = referenceManager.getReferencesTo(extSym.getAddress());
                 while(refIter.hasNext()){
                     monitor.checkCancelled();
                     Reference ref = refIter.next();
                     Address refAddr = ref.getFromAddress();

                     // Check if already reported
                     if (!reportedReferenceAddresses.add(refAddr)) continue;

                     Function callingFunc = functionManager.getFunctionContaining(refAddr);
                     String funcName = getFunctionName(callingFunc);
                     String category = config.getApiCategory(apiName);
                     String description = config.getRuleDescription(apiName);

                     if (!foundAnyRefForThisApi) {
                         logger.accept(String.format("Found references related to '%s':\n", apiName));
                         foundAnyRefForThisApi = true;
                     }
                     logger.accept(String.format("  - External Call at 0x%s (in function %s)\n", refAddr, funcName));

                     // Add Finding
                     findings.add(new Finding(refAddr, "API", apiName, Severity.MEDIUM, description, funcName));

                     // Annotate
                     addBookmark(bookmarkManager, refAddr, BOOKMARK_CATEGORY_API + ": " + category, apiName + " - " + description);
                     setPreComment(listing, refAddr, category + ": " + apiName);
                     setBackgroundColor(program, refAddr, API_COLOR);
                     apiFoundCount++;
                 }
            }

            // --- Search Internal Functions ---
            FunctionIterator functions = functionManager.getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function func = functions.next();
                // Use getName(true) for namespace, check case-insensitively
                if (func.getName(true).equalsIgnoreCase(apiName)) {
                     ReferenceIterator refIter = referenceManager.getReferencesTo(func.getEntryPoint());
                     while(refIter.hasNext()) {
                         monitor.checkCancelled();
                         Reference ref = refIter.next();
                         Address refAddr = ref.getFromAddress();

                         // Check if already reported
                         if (!reportedReferenceAddresses.add(refAddr)) continue;

                         Function callingFunc = functionManager.getFunctionContaining(refAddr);
                         String funcName = getFunctionName(callingFunc);
                         String category = config.getApiCategory(apiName);
                         String description = config.getRuleDescription(apiName);

                         if (!foundAnyRefForThisApi) {
                             logger.accept(String.format("Found references related to '%s':\n", apiName));
                             foundAnyRefForThisApi = true;
                          }
                         logger.accept(String.format("  - Internal Call at 0x%s (in function %s)\n", refAddr, funcName));

                         // Add Finding
                         findings.add(new Finding(refAddr, "API", apiName, Severity.MEDIUM, description, funcName));

                         // Annotate
                         addBookmark(bookmarkManager, refAddr, BOOKMARK_CATEGORY_API + ": " + category, apiName + " - " + description);
                         setPreComment(listing, refAddr, category + ": " + apiName);
                         setBackgroundColor(program, refAddr, API_COLOR);
                         apiFoundCount++;
                     }
                }
            }

            // --- Search Data Labels --- (New Functionality)
            SymbolIterator labelSymbols = symbolTable.getSymbolIterator(apiName, true); // Find symbols by name
             while (labelSymbols.hasNext()) {
                 monitor.checkCancelled();
                 Symbol labelSym = labelSymbols.next();
                 // Only process if it's a LABEL symbol type
                 if (labelSym.getSymbolType() == SymbolType.LABEL) {
                     ReferenceIterator refIter = referenceManager.getReferencesTo(labelSym.getAddress());
                     while(refIter.hasNext()){
                         monitor.checkCancelled();
                         Reference ref = refIter.next();
                         Address refAddr = ref.getFromAddress();

                         // Check if already reported
                         if (!reportedReferenceAddresses.add(refAddr)) continue;

                         Function callingFunc = functionManager.getFunctionContaining(refAddr);
                         String funcName = getFunctionName(callingFunc);
                         String category = config.getApiCategory(apiName);
                         // Use a specific description or the generic one? Using generic for now.
                         String description = config.getRuleDescription(apiName);

                         if (!foundAnyRefForThisApi) {
                             logger.accept(String.format("Found references related to '%s':\n", apiName));
                             foundAnyRefForThisApi = true;
                         }
                         logger.accept(String.format("  - Label Ref at 0x%s (in function %s) -> Label '%s' at 0x%s\n",
                                 refAddr, funcName, labelSym.getName(), labelSym.getAddress()));

                         // Add Finding (Use distinct type)
                         findings.add(new Finding(refAddr, "API Label Ref", apiName, Severity.LOW, // Lower severity for label refs?
                                 "Reference to data label named '" + apiName + "'", funcName));

                         // Annotate differently
                         addBookmark(bookmarkManager, refAddr, BOOKMARK_CATEGORY_API_LABEL + ": " + category,
                                 "Ref to Label: " + apiName + " - " + description);
                         setPreComment(listing, refAddr, category + ": Ref to Label " + apiName);
                         setBackgroundColor(program, refAddr, API_LABEL_COLOR); // Use different color
                         apiFoundCount++;
                     }
                 }
             }
        }
         logger.accept("API/Function/Label search finished. Found " + apiFoundCount + " references.\n");
    }

    /** Analyzes keyword patterns based on the configuration, including cross-reference checks. */
    private static void analyzeKeywordPatterns(Program program, AntiDebugConfig config, Consumer<String> logger, TaskMonitor monitor, List<Finding> findings) throws CancelledException {
        Listing listing = program.getListing();
        Memory memory = program.getMemory();
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager referenceManager = program.getReferenceManager(); // Needed for XRefs

        logger.accept("\n--- Searching for Keyword Patterns (Direct & XRef) ---\n");
        int groupsFoundCount = 0;
        Set<Address> annotatedPatternAddresses = new HashSet<>(); // Prevent duplicate annotations

        // Iterate through all executable code units
        AddressSetView addresses = memory.getExecuteSet();
        if (addresses.isEmpty()) {
            logger.accept("No executable memory regions found to scan for keyword patterns.\n");
            return;
        }

        // Use a map to store potential primary keyword hits and the groups they belong to
        Map<Address, List<AntiDebugConfig.KeywordGroup>> primaryKeywordHits = new LinkedHashMap<>();

        // Pass 1: Find all primary keywords
        logger.accept("Scanning for primary keywords...\n");
        monitor.setMessage("Scanning for primary keywords...");
        CodeUnitIterator codeUnits = listing.getCodeUnits(addresses, true); // Iterate forward
        monitor.initialize(addresses.getNumAddresses()); // Progress based on addresses
        long progress = 0;

        while (codeUnits.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = codeUnits.next();
            if (cu.getMinAddress() != null) {
                 try {
                    progress = cu.getMinAddress().subtract(addresses.getMinAddress());
                    monitor.setProgress(progress);
                 } catch (AddressOverflowException e) { /* ignore progress update issue */ }
            }

            for (AntiDebugConfig.KeywordGroup group : config.getKeywordGroups()) {
                monitor.checkCancelled();
                String primaryKeyword = group.getPrimaryKeyword();
                if (isKeywordFound(cu, primaryKeyword, program)) {
                    primaryKeywordHits.computeIfAbsent(cu.getAddress(), k -> new ArrayList<>()).add(group);
                }
            }
        }
        logger.accept("Found " + primaryKeywordHits.size() + " potential primary keyword locations.\n");
        if (monitor.isCancelled()) throw new CancelledException();

        // Pass 2: Search for subsequent keywords starting from primary hits (Direct & XRef)
        logger.accept("Searching for subsequent keywords (Direct & XRef)...\n");
        monitor.setMessage("Searching for subsequent keywords...");
        monitor.initialize(primaryKeywordHits.size());
        progress = 0;

        for (Map.Entry<Address, List<AntiDebugConfig.KeywordGroup>> entry : primaryKeywordHits.entrySet()) {
            monitor.checkCancelled();
            monitor.setProgress(++progress);
            Address primaryAddr = entry.getKey();
            List<AntiDebugConfig.KeywordGroup> potentialGroups = entry.getValue();

            for (AntiDebugConfig.KeywordGroup group : potentialGroups) {
                monitor.checkCancelled();
                monitor.setMessage("Checking group: " + group.getName() + " at " + primaryAddr);

                Function func = functionManager.getFunctionContaining(primaryAddr);
                String funcName = getFunctionName(func);
                boolean foundDirectly = false; // Flag to track if found via direct search

                // --- Handle Single Keyword Rules ---
                if (group.getKeywords().size() == 1) {
                    if (annotatedPatternAddresses.add(primaryAddr)) { // Check if already annotated
                        logger.accept(String.format("Found Single keyword Rule '%s' ('%s') at 0x%s (in function %s)\n",
                            group.getName(), group.getPrimaryKeyword(), primaryAddr, funcName));
                        findings.add(new Finding(primaryAddr, "Keyword", group.getName(), Severity.MEDIUM, group.getDescription(), funcName));
                        addBookmark(bookmarkManager, primaryAddr, BOOKMARK_CATEGORY_PATTERN + ": " + group.getName(), group.getDescription());
                        setPreComment(listing, primaryAddr, BOOKMARK_CATEGORY_PATTERN + ": " + group.getName());
                        setPostComment(listing, primaryAddr, group.getDescription());
                        setBackgroundColor(program, primaryAddr, PATTERN_PRIMARY_COLOR);
                        groupsFoundCount++;
                    }
                    continue; // Move to next group for this primary address
                }

                // --- Handle Multi-Keyword Rules (Direct Search First) ---
                Address lastFoundAddrDirect = primaryAddr;
                boolean allSubsequentFoundDirect = true;
                List<Address> foundAddressesDirect = new ArrayList<>();
                foundAddressesDirect.add(primaryAddr);

                for (int i = 1; i < group.getKeywords().size(); i++) {
                    monitor.checkCancelled();
                    String keywordToFind = group.getKeywordByIndex(i);
                    Address searchStart = lastFoundAddrDirect.add(1);
                    Address nextAddr = findKeywordInRange(program, listing, searchStart, keywordToFind, group.getSearchRange(), monitor);

                    if (nextAddr != null) {
                        lastFoundAddrDirect = nextAddr;
                        foundAddressesDirect.add(nextAddr);
                    } else {
                        allSubsequentFoundDirect = false;
                        break;
                    }
                }

                if (allSubsequentFoundDirect) {
                    foundDirectly = true; // Mark as found directly
                    if (annotatedPatternAddresses.add(primaryAddr)) { // Only report/annotate if primary hasn't been part of another reported pattern
                        logger.accept(String.format("Found Keyword group '%s' (Direct) starting at 0x%s (in function %s)\n",
                            group.getName(), primaryAddr, funcName));
                        findings.add(new Finding(primaryAddr, "Keyword Group", group.getName(), Severity.HIGH, group.getDescription(), funcName));
                        addBookmark(bookmarkManager, primaryAddr, BOOKMARK_CATEGORY_PATTERN + ": " + group.getName(), group.getDescription());
                        setPreComment(listing, primaryAddr, BOOKMARK_CATEGORY_PATTERN + ": " + group.getName());
                        setPostComment(listing, primaryAddr, group.getDescription());
                        setBackgroundColor(program, primaryAddr, PATTERN_PRIMARY_COLOR);

                        for (int i = 1; i < foundAddressesDirect.size(); i++) {
                             Address subsequentAddr = foundAddressesDirect.get(i);
                             logger.accept(String.format("  - Keyword '%s' found at 0x%s\n", group.getKeywordByIndex(i), subsequentAddr));
                             if (annotatedPatternAddresses.add(subsequentAddr)) { // Avoid re-annotating secondary hits too
                                addBookmark(bookmarkManager, subsequentAddr, BOOKMARK_CATEGORY_PATTERN_PART + ": " + group.getName(), "Keyword: " + group.getKeywordByIndex(i));
                                setBackgroundColor(program, subsequentAddr, PATTERN_SECONDARY_COLOR);
                             }
                        }
                        groupsFoundCount++;
                    }
                }

                // --- Cross-Reference Check (Only if Direct Search Failed) --- (New Functionality)
                if (!foundDirectly && group.getKeywords().size() > 1) {
                    monitor.setMessage("Checking XRefs for group: " + group.getName() + " from " + primaryAddr);
                    ReferenceIterator refIter = referenceManager.getReferencesTo(primaryAddr);
                    boolean foundViaXref = false;

                    while(refIter.hasNext() && !monitor.isCancelled()){
                        Reference ref = refIter.next();
                        Address xrefAddr = ref.getFromAddress(); // Address where the primary keyword is referenced from

                        // Now, try the sequence search starting strictly AFTER the cross-reference location
                        Address lastFoundAddrXref = xrefAddr;
                        boolean allSubsequentFoundXref = true;
                        List<Address> foundAddressesXref = new ArrayList<>();
                        foundAddressesXref.add(xrefAddr); // Start sequence from the xref location

                        for (int i = 1; i < group.getKeywords().size(); i++) { // Start checking from the SECOND keyword
                            monitor.checkCancelled();
                            String keywordToFind = group.getKeywordByIndex(i);
                            Address searchStart = lastFoundAddrXref.add(1); // Search after previous hit in this xref sequence
                            Address nextAddr = findKeywordInRange(program, listing, searchStart, keywordToFind, group.getSearchRange(), monitor);

                            if (nextAddr != null) {
                                lastFoundAddrXref = nextAddr;
                                foundAddressesXref.add(nextAddr);
                            } else {
                                allSubsequentFoundXref = false;
                                break; // Stop checking this specific xref path
                            }
                        }

                        // If the full sequence was found starting from this xref
                        if (allSubsequentFoundXref) {
                             if (annotatedPatternAddresses.add(xrefAddr)) { // Check if xref start already annotated
                                logger.accept(String.format("Found Keyword group '%s' (XRef from 0x%s) starting at 0x%s (in function %s)\n",
                                    group.getName(), primaryAddr, xrefAddr, getFunctionName(functionManager.getFunctionContaining(xrefAddr))));

                                // Add Finding, noting it was found via XRef
                                findings.add(new Finding(xrefAddr, "Keyword Group (XRef)", group.getName(), Severity.HIGH,
                                        group.getDescription() + " [Found via XRef from " + primaryAddr + "]",
                                        getFunctionName(functionManager.getFunctionContaining(xrefAddr))));

                                // Annotate differently to indicate XRef find
                                addBookmark(bookmarkManager, xrefAddr, BOOKMARK_CATEGORY_PATTERN_XREF + ": " + group.getName(),
                                        group.getDescription() + " [XRef from " + primaryAddr + "]");
                                setPreComment(listing, xrefAddr, BOOKMARK_CATEGORY_PATTERN_XREF + ": " + group.getName());
                                setPostComment(listing, xrefAddr, group.getDescription() + " [XRef]");
                                setBackgroundColor(program, xrefAddr, PATTERN_PRIMARY_COLOR); // Use primary for start

                                // Annotate subsequent parts
                                for (int i = 1; i < foundAddressesXref.size(); i++) {
                                     Address subsequentAddr = foundAddressesXref.get(i);
                                     logger.accept(String.format("  - Keyword '%s' found at 0x%s\n", group.getKeywordByIndex(i), subsequentAddr));
                                     if (annotatedPatternAddresses.add(subsequentAddr)) {
                                        addBookmark(bookmarkManager, subsequentAddr, BOOKMARK_CATEGORY_PATTERN_PART + ": " + group.getName() + " (XRef)", "Keyword: " + group.getKeywordByIndex(i));
                                        setBackgroundColor(program, subsequentAddr, PATTERN_SECONDARY_COLOR);
                                     }
                                }
                                groupsFoundCount++;
                                foundViaXref = true;
                                break; // Found via one xref, stop checking other xrefs for this primaryAddr/group combo
                             }
                        }
                    } // End while loop for references
                } // End if (!foundDirectly)

            } // end loop through potential groups for this primary address
        } // end loop through primary hits

        logger.accept("Keyword pattern search finished. Found " + groupsFoundCount + " matching groups/rules (Direct + XRef).\n");
    }

    /** Analyzes instruction sequences and patterns based on the configuration. */
    private static void analyzeInstructions(Program program, AntiDebugConfig config, Consumer<String> logger, TaskMonitor monitor, List<Finding> findings) throws CancelledException {
        List<InstructionRule> instructionRules = config.getInstructionRules();
        if (instructionRules.isEmpty()) {
            logger.accept("Skipping Instruction analysis (no rules configured).\n");
            return; // Skip if no instruction rules configured
        }

        logger.accept("\n--- Searching for Instruction Patterns ---\n");
        Listing listing = program.getListing();
        FunctionManager functionManager = program.getFunctionManager();
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        Set<Address> annotatedInstructionAddresses = new HashSet<>(); // Prevent duplicate annotations

        int rulesFoundCount = 0;

        // Iterate through all functions
        FunctionIterator functions = functionManager.getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            monitor.setMessage("Analyzing function for instruction patterns: " + getFunctionName(func));

            // Iterate through all instructions within the function
            InstructionIterator instructions = listing.getInstructions(func.getBody(), true);
            while (instructions.hasNext() && !monitor.isCancelled()) {
                Instruction currentInstruction = instructions.next();
                Address currentAddr = currentInstruction.getAddress();

                // Check if this address was already annotated as the start of a sequence
                if (annotatedInstructionAddresses.contains(currentAddr)) {
                    continue;
                }

                // For each instruction, check if it's the start of any defined instruction rule sequence
                for (InstructionRule rule : instructionRules) {
                    monitor.checkCancelled(); // Check per rule

                    // Attempt to match the instruction sequence starting from the current instruction
                    if (matchInstructionSequence(program, listing, currentInstruction, rule, monitor)) {
                        String funcName = getFunctionName(func);
                        String description = config.getRuleDescription(rule.getName());

                        logger.accept(String.format("Found Instruction Rule '%s' starting at 0x%s (in function %s)\n",
                            rule.getName(), currentAddr, funcName));

                        // Add Finding for the start of the sequence
                        findings.add(new Finding(currentAddr, "Instruction Sequence", rule.getName(), Severity.HIGH, description, funcName));

                        // Annotate the starting instruction
                        addBookmark(bookmarkManager, currentAddr, BOOKMARK_CATEGORY_INSTRUCTION + ": " + rule.getName(), description);
                        setPreComment(listing, currentAddr, BOOKMARK_CATEGORY_INSTRUCTION + ": " + rule.getName());
                        setPostComment(listing, currentAddr, description);
                        setBackgroundColor(program, currentAddr, INSTRUCTION_COLOR);
                        annotatedInstructionAddresses.add(currentAddr); // Mark as annotated

                        rulesFoundCount++;
                        // Found a match starting here, break inner loop (don't check other rules starting at same addr)
                        break;
                    }
                }
            }
        }

        logger.accept("Instruction pattern search finished. Found " + rulesFoundCount + " matching rules.\n");
    }

    /**
     * Attempts to match a configured instruction sequence rule starting from a given instruction.
     * (Includes corrected operand checking logic)
     */
    private static boolean matchInstructionSequence(Program program, Listing listing, Instruction startInstruction, InstructionRule rule, TaskMonitor monitor) throws CancelledException {
        Instruction currentInstruction = startInstruction;
        for (InstructionStep step : rule.getSteps()) {
            monitor.checkCancelled();

            if (currentInstruction == null) {
                return false; // Reached end of instruction stream before matching all steps
            }

            // 1. Check Mnemonic (Case-insensitive)
            if (!currentInstruction.getMnemonicString().equalsIgnoreCase(step.getMnemonic())) {
                return false; // Mnemonic doesn't match
            }

            // 2. Check Operand Constraints
            for (OperandCheck check : step.getOperandChecks()) {
                monitor.checkCancelled();
                int opIndex = check.getOperandIndex();
                if (opIndex >= currentInstruction.getNumOperands()) {
                    return false; // Rule requires an operand that doesn't exist
                }

                boolean operandMatches = false;
                switch (check.getCheckType()) {
                    case REG:
                        Register reg = currentInstruction.getRegister(opIndex);
                        if (reg != null && reg.getName().equalsIgnoreCase(check.getValue())) {
                            operandMatches = true;
                        }
                        break;
                    case VAL:
                        Scalar scalar = currentInstruction.getScalar(opIndex);
                        if (scalar != null) {
                            try {
                                long checkValue;
                                String valStr = check.getValue().toLowerCase();
                                if (valStr.startsWith("0x")) {
                                    checkValue = NumericUtilities.parseHexLong(valStr);
                                } else if (valStr.startsWith("-")) {
                                    checkValue = Long.parseLong(valStr);
                                } else {
                                    checkValue = Long.parseUnsignedLong(valStr);
                                }
                                if (scalar.getSignedValue() == checkValue || scalar.getUnsignedValue() == checkValue) {
                                    operandMatches = true;
                                }
                            } catch (NumberFormatException e) {
                                Msg.warn(AntiDebugAnalysisCore.class, String.format("Invalid VAL format '%s' for rule '%s' at %s. Check config.",
                                        check.getValue(), rule.getName(), currentInstruction.getAddress()));
                            }
                        }
                        break;
                    case TYPE:
                        int opType = currentInstruction.getOperandType(opIndex);
                        String typeStr = OperandType.toString(opType);
                        if (typeStr.equalsIgnoreCase(check.getValue())) {
                            operandMatches = true;
                        }
                        break;
                    default:
                         Msg.error(AntiDebugAnalysisCore.class, "Unsupported OperandCheck.CheckType encountered: " + check.getCheckType());
                         break;
                }

                if (!operandMatches) {
                    return false; // Operand check failed for this step
                }
            } // End operand checks loop

            // Move to the next instruction for the next step
            currentInstruction = currentInstruction.getNext();

        } // End steps loop

        // If we successfully matched all steps in the rule
        return true;
    }


    /** Analyzes byte sequences based on the configuration. */
    private static void analyzeBytes(Program program, AntiDebugConfig config, Consumer<String> logger, TaskMonitor monitor, List<Finding> findings) throws CancelledException {
        List<String> byteSequences = config.getByteSequences();
        if (byteSequences.isEmpty()) {
             logger.accept("Skipping Byte Sequence analysis (no sequences configured).\n");
             return;
        }

        logger.accept("\n--- Searching for Byte Sequences ---\n");
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        Set<Address> annotatedByteAddresses = new HashSet<>(); // Prevent duplicate annotations
        int foundCount = 0;

        for (String byteSequenceHex : byteSequences) {
             monitor.checkCancelled();
             monitor.setMessage("Bytes: " + byteSequenceHex);
             byte[] searchBytes;
             try {
                 searchBytes = NumericUtilities.convertHexStringToBytes(byteSequenceHex.replaceAll("\\s", ""));
                 if (searchBytes.length == 0) {
                     Msg.warn(AntiDebugAnalysisCore.class, "Empty byte sequence configured: " + byteSequenceHex);
                     continue;
                 }
             } catch (NumberFormatException e) {
                 Msg.error(AntiDebugAnalysisCore.class, "Invalid hex string in config: " + byteSequenceHex, e);
                 continue;
             }

             // Search through all memory blocks
             Address startAddr = program.getMinAddress();
             while (startAddr != null && !monitor.isCancelled()) {
                 Address foundAddr = memory.findBytes(startAddr, searchBytes, null, true, monitor);
                 if (foundAddr == null) {
                     break;
                 }

                 // Check if already annotated
                 if (annotatedByteAddresses.add(foundAddr)) {
                     Function func = listing.getFunctionContaining(foundAddr);
                     String funcName = getFunctionName(func);
                     String ruleName = byteSequenceHex;
                     String description = config.getRuleDescription(ruleName);

                     logger.accept(String.format("Found byte sequence '%s' at 0x%s (in function %s)\n",
                             byteSequenceHex, foundAddr, funcName));

                     findings.add(new Finding(foundAddr, "Bytes", ruleName, Severity.LOW, description, funcName));

                     addBookmark(bookmarkManager, foundAddr, BOOKMARK_CATEGORY_BYTES, ruleName + " - " + description);
                     setBackgroundColor(program, foundAddr, BYTES_COLOR);
                     setPreComment(listing, foundAddr, BOOKMARK_CATEGORY_BYTES + ": " + ruleName);
                     if (!description.equals(config.getRuleDescription(""))) {
                        setPostComment(listing, foundAddr, description);
                     }
                     foundCount++;
                 }

                 // Prepare for the next search *after* the current find
                 try {
                    startAddr = foundAddr.addNoWrap(1);
                 } catch (AddressOverflowException e) {
                     startAddr = null;
                 }
             } // end while occurrences
        } // end for each sequence
        logger.accept("Byte sequence search finished. Found " + foundCount + " matches.\n");
    }


    // =====================================================================================
    // Keyword Searching Helpers
    // =====================================================================================

    /** Checks if a keyword is found in a CodeUnit (Instruction or Data). Handles mnemonics, operands, and labels. */
    private static boolean isKeywordFound(CodeUnit cu, String keyword, Program program) {
        if (cu == null || keyword == null || keyword.isEmpty()) {
            return false;
        }

        // 1. Check Instruction Mnemonic and Operands
        if (cu instanceof Instruction ins) {
            if (ins.getMnemonicString().equalsIgnoreCase(keyword)) {
                return true;
            }
            for (int i = 0; i < ins.getNumOperands(); i++) {
                boolean keywordIsHex = keyword.toLowerCase().startsWith("0x");
                Register reg = ins.getRegister(i);
                if (reg != null && reg.getName().equalsIgnoreCase(keyword)) {
                    return true;
                }
                Scalar scalar = ins.getScalar(i);
                if (scalar != null && keywordIsHex) {
                     try {
                         long keywordVal = NumericUtilities.parseHexLong(keyword);
                         if (scalar.getUnsignedValue() == keywordVal || scalar.getSignedValue() == keywordVal) {
                             return true;
                         }
                     } catch (NumberFormatException e) { /* ignore */ }
                }
                String opRep = ins.getDefaultOperandRepresentation(i);
                if (opRep != null) {
                     if (!keywordIsHex && opRep.toLowerCase().contains(keyword.toLowerCase())) {
                         return true;
                     }
                     if (keywordIsHex && opRep.equalsIgnoreCase(keyword)) {
                         return true;
                     }
                }
            }
        }
        // 2. Check Data (Optional - currently disabled for performance/focus)
        // else if (cu instanceof Data data) { ... }

        // 3. Check Labels at the CodeUnit's address
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol[] symbols = symbolTable.getSymbols(cu.getAddress());
        for (Symbol symbol : symbols) {
            if (symbol.getName().toLowerCase().contains(keyword.toLowerCase())) {
                return true;
            }
        }
        return false;
    }


     /** Finds the *first* occurrence of the keyword within the specified byte range, starting search *at or after* startAddress. */
    private static Address findKeywordInRange(Program program, Listing listing, Address startAddress, String keyword, int range, TaskMonitor monitor) throws CancelledException {
        if (startAddress == null || keyword == null || keyword.isEmpty() || range <= 0) {
            return null;
        }

        Address currentSearchAddr = startAddress;
        Address maxSearchAddr;
        Address maxProgAddr = program.getMaxAddress();

        try {
            maxSearchAddr = startAddress.addNoWrap(range - 1);
             if (maxSearchAddr.compareTo(maxProgAddr) > 0) {
                maxSearchAddr = maxProgAddr;
            }
        } catch (AddressOverflowException e) {
            maxSearchAddr = maxProgAddr;
        }

        // Get code units starting *at* startAddress within the range
        CodeUnitIterator codeUnits = listing.getCodeUnits(new AddressSet(startAddress, maxSearchAddr), true);

        while (codeUnits.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = codeUnits.next();
            if (isKeywordFound(cu, keyword, program)) {
                return cu.getAddress(); // Found it
            }
        }
        return null; // Not found
    }


    // =====================================================================================
    // Annotation Utilities
    // =====================================================================================

    /** Adds a bookmark with category and comment. */
    private static void addBookmark(BookmarkManager bookmarkManager, Address addr, String category, String comment) {
        if (bookmarkManager == null || addr == null || category == null || comment == null) return;
        String shortComment = comment.length() > 200 ? comment.substring(0, 197) + "..." : comment;
        try {
             bookmarkManager.setBookmark(addr, BookmarkType.ANALYSIS, category, shortComment);
        } catch (Exception e) {
             Msg.error(AntiDebugAnalysisCore.class, "Error setting bookmark at " + addr + ": " + e.getMessage(), e);
        }
    }

    /** Sets or appends to the pre-comment at the given address. */
    private static void setPreComment(Listing listing, Address address, String comment) {
        if (listing == null || address == null || comment == null || comment.isBlank()) return;
        try {
            CodeUnit cu = listing.getCodeUnitAt(address);
            if (cu != null) {
                String existing = cu.getComment(CodeUnit.PRE_COMMENT);
                String newComment;
                if (existing == null || existing.isBlank()) {
                    newComment = comment;
                } else if (!existing.contains(comment)) {
                    newComment = existing + "\n" + comment;
                } else {
                    return; // Comment already exists
                }
                cu.setComment(CodeUnit.PRE_COMMENT, newComment.trim());
            }
        } catch (Exception e) {
             Msg.error(AntiDebugAnalysisCore.class, "Error setting pre-comment at " + address + ": " + e.getMessage(), e);
        }
    }

    /** Sets or appends to the post-comment at the given address. */
     private static void setPostComment(Listing listing, Address address, String comment) {
        if (listing == null || address == null || comment == null || comment.isBlank()) return;
         try {
            CodeUnit cu = listing.getCodeUnitAt(address);
            if (cu != null) {
                String existing = cu.getComment(CodeUnit.POST_COMMENT);
                String newComment;
                if (existing == null || existing.isBlank()) {
                    newComment = comment;
                } else if (!existing.contains(comment)) {
                    newComment = existing + "\n" + comment;
                } else {
                    return; // Comment already exists
                }
                cu.setComment(CodeUnit.POST_COMMENT, newComment.trim());
            }
         } catch (Exception e) {
             Msg.error(AntiDebugAnalysisCore.class, "Error setting post-comment at " + address + ": " + e.getMessage(), e);
         }
    }

    /** Sets the background color for a given address range (typically single address). */
    private static void setBackgroundColor(Program program, Address address, Color color) {
        if (program == null || address == null || color == null) return;
         try {
             ServiceProvider serviceProvider = null;
             // Attempt to get the tool context if available (e.g., running as plugin)
             if (program.getDomainFile() != null && program.getDomainFile().getTool() != null) {
                 serviceProvider = program.getDomainFile().getTool();
             }

             BackgroundColorModel colorModel = null;
             if(serviceProvider != null) {
                 colorModel = serviceProvider.getService(BackgroundColorModel.class);
             }

             if (colorModel != null) {
                  colorModel.setBackgroundColor(address, address, color);
             } else {
                 // Only warn if we might have expected it
                 if (serviceProvider != null) {
                    Msg.warn(AntiDebugAnalysisCore.class, "BackgroundColorModel service not available. Cannot set background color.");
                 } // else: likely running headless/script without GUI tool, don't warn
             }
         } catch (Exception e) {
             // Catch broader exceptions as getTool() or getService() might throw them
             Msg.error(AntiDebugAnalysisCore.class, "Error setting background color at " + address + ": " + e.getMessage(), e);
         }
    }

    /** Safely gets the function name including namespace or "N/A". */
    private static String getFunctionName(Function func) {
        return (func != null) ? func.getName(true) : "N/A";
    }
}
