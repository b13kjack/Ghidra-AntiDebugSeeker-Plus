package antidebugseeker;

// --- Necessary Imports (Ignoring resolution errors) ---
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.NumericUtilities;

import java.awt.Color;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
// --- End Imports ---

/**
 * Core analysis engine for the AntiDebugSeeker plugin.
 * Performs searches for API calls, keyword patterns, instructions, and byte sequences.
 */
public class AntiDebugAnalysisCore {

    // --- Constants ---
    private static final Color API_COLOR = new Color(173, 255, 47, 128); // Light green (semi-transparent)
    private static final Color PATTERN_PRIMARY_COLOR = new Color(255, 165, 0, 128); // Orange (semi-transparent)
    private static final Color PATTERN_SECONDARY_COLOR = new Color(255, 200, 120, 128); // Lighter orange (semi-transparent)
    private static final String BOOKMARK_CATEGORY_API = "AntiDebug API";
    private static final String BOOKMARK_CATEGORY_PATTERN = "AntiDebug Pattern";
    private static final String BOOKMARK_CATEGORY_PATTERN_PART = "Pattern Part";
    private static final String BOOKMARK_CATEGORY_INSTRUCTION = "AntiDebug Instruction"; // Example
    private static final String BOOKMARK_CATEGORY_BYTES = "AntiDebug Bytes";       // Example

    /** Private constructor to prevent instantiation. */
    private AntiDebugAnalysisCore() {}

    /** Represents a single finding during analysis. */
    private record Finding(
        Address address,
        String type, // e.g., "API", "Keyword Group", "Instruction", "Bytes"
        String ruleName, // Name of the API, Keyword Group, etc.
        String description,
        String functionContext // Name of the containing function, or "N/A"
    ) {
        /** Creates a Finding, ensuring non-null values where appropriate. */
        Finding {
            Objects.requireNonNull(address, "Finding address cannot be null");
            Objects.requireNonNull(type, "Finding type cannot be null");
            Objects.requireNonNull(ruleName, "Finding ruleName cannot be null");
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
        logger.accept("Starting Anti-Debug Analysis...");
        List<Finding> findings = new ArrayList<>(); // Store all findings

        // --- Perform Enabled Analyses ---
        if (config.isAnalyzeApiCallsEnabled()) {
            monitor.setMessage("Analyzing API Calls...");
            analyzeApiCalls(program, config, logger, monitor, findings);
            monitor.checkCancelled();
        } else {
            logger.accept("Skipping API Call analysis (disabled in config).");
        }

        if (config.isAnalyzeKeywordsEnabled()) {
            monitor.setMessage("Analyzing Keyword Patterns...");
            analyzeKeywordPatterns(program, config, logger, monitor, findings);
            monitor.checkCancelled();
        } else {
            logger.accept("Skipping Keyword Pattern analysis (disabled in config).");
        }

        if (config.isAnalyzeInstructionsEnabled()) {
            monitor.setMessage("Analyzing Instructions...");
            analyzeInstructions(program, config, logger, monitor, findings);
            monitor.checkCancelled();
        } else {
            logger.accept("Skipping Instruction analysis (disabled in config).");
        }

        if (config.isAnalyzeBytesEnabled()) {
            monitor.setMessage("Analyzing Byte Sequences...");
            analyzeBytes(program, config, logger, monitor, findings);
            monitor.checkCancelled();
        } else {
             logger.accept("Skipping Byte Sequence analysis (disabled in config).");
        }

        // --- Finalize and Report ---
        logger.accept("\nAnalysis Complete.");
        logger.accept("--- Summary ---");
        logger.accept(String.format(" - API Patterns Searched: %d (%s)", config.getApiCalls().size(), config.isAnalyzeApiCallsEnabled() ? "Enabled" : "Disabled"));
        logger.accept(String.format(" - Keyword Groups Searched: %d (%s)", config.getKeywordGroups().size(), config.isAnalyzeKeywordsEnabled() ? "Enabled" : "Disabled"));
        logger.accept(String.format(" - Instruction Patterns Searched: %d (%s)", config.getInstructions().size(), config.isAnalyzeInstructionsEnabled() ? "Enabled" : "Disabled"));
        logger.accept(String.format(" - Byte Sequences Searched: %d (%s)", config.getByteSequences().size(), config.isAnalyzeBytesEnabled() ? "Enabled" : "Disabled"));
        logger.accept("Total Findings: " + findings.size());
        logger.accept("See details above and Bookmarks panel for findings.");

        // --- CSV Output (New Feature) ---
        if (config.isCsvOutputEnabled()) {
            monitor.setMessage("Writing results to CSV...");
            Path outputPath = config.getCsvOutputPath();
            if (outputPath != null) {
                try {
                    CsvResultWriter.writeResults(outputPath, findings);
                    logger.accept("Results successfully written to: " + outputPath);
                } catch (IOException e) {
                    logger.accept("Error writing CSV results: " + e.getMessage());
                    Msg.error(AntiDebugAnalysisCore.class, "Failed to write CSV results to " + outputPath, e);
                }
            } else {
                logger.accept("CSV output enabled, but no output path specified in config.");
                Msg.warn(AntiDebugAnalysisCore.class, "CSV output enabled but csv_output_path is not set in config.");
            }
        }
    }

    // =====================================================================================
    // Analysis Methods
    // =====================================================================================

    /** Analyzes API calls based on the configuration. */
    private static void analyzeApiCalls(Program program, AntiDebugConfig config, Consumer<String> logger, TaskMonitor monitor, List<Finding> findings) throws CancelledException {
        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager referenceManager = program.getReferenceManager();
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        Listing listing = program.getListing();

        logger.accept("\n--- Searching for API Calls ---");
        int apiFoundCount = 0;

        for (String apiName : config.getApiCalls()) {
            monitor.checkCancelled();
            monitor.setMessage("API: " + apiName);
            boolean foundAnyRefForThisApi = false;

            // Search external symbols
            SymbolIterator externalSymbols = symbolTable.getExternalSymbolIterator(apiName);
             while (externalSymbols.hasNext()) {
                 monitor.checkCancelled();
                 Symbol extSym = externalSymbols.next();
                 ReferenceIterator refIter = referenceManager.getReferencesTo(extSym.getAddress());
                 while(refIter.hasNext()){
                     monitor.checkCancelled();
                     Reference ref = refIter.next();
                     Address refAddr = ref.getFromAddress();
                     Function callingFunc = functionManager.getFunctionContaining(refAddr);
                     String funcName = getFunctionName(callingFunc);
                     String category = config.getApiCategory(apiName);
                     String description = config.getRuleDescription(apiName); // Use unified description getter

                     if (!foundAnyRefForThisApi) {
                         logger.accept(String.format("Found API call '%s' (External Symbol):", apiName));
                         foundAnyRefForThisApi = true;
                     }
                     logger.accept(String.format("  - 0x%s (in function %s)", refAddr, funcName));

                     // Add Finding
                     findings.add(new Finding(refAddr, "API", apiName, description, funcName));

                     // Annotate
                     addBookmark(bookmarkManager, refAddr, BOOKMARK_CATEGORY_API + ": " + category, apiName + " - " + description);
                     setPreComment(listing, refAddr, category + ": " + apiName);
                     setBackgroundColor(program, refAddr, API_COLOR);
                     apiFoundCount++;
                 }
            }

            FunctionIterator functions = functionManager.getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function func = functions.next();
                if (func.getName(true).equalsIgnoreCase(apiName)) { // Case-insensitive match
                     ReferenceIterator refIter = referenceManager.getReferencesTo(func.getEntryPoint());
                     while(refIter.hasNext()) {
                         monitor.checkCancelled();
                         Reference ref = refIter.next();
                         Address refAddr = ref.getFromAddress();
                         Function callingFunc = functionManager.getFunctionContaining(refAddr);
                         String funcName = getFunctionName(callingFunc);
                         String category = config.getApiCategory(apiName);
                         String description = config.getRuleDescription(apiName);

                         if (!foundAnyRefForThisApi) {
                             logger.accept(String.format("Found function matching API name '%s' at 0x%s, referenced by:", func.getName(true), func.getEntryPoint()));
                             foundAnyRefForThisApi = true;
                          }
                         logger.accept(String.format("  - 0x%s (in function %s)", refAddr, funcName));

                         // Add Finding
                         findings.add(new Finding(refAddr, "API", apiName, description, funcName));

                         // Annotate
                         addBookmark(bookmarkManager, refAddr, BOOKMARK_CATEGORY_API + ": " + category, apiName + " - " + description);
                         setPreComment(listing, refAddr, category + ": " + apiName);
                         setBackgroundColor(program, refAddr, API_COLOR);
                         apiFoundCount++;
                     }
                }
            }
        }
         logger.accept("API Call search finished. Found " + apiFoundCount + " references.");
    }

    /** Analyzes keyword patterns based on the configuration. */
    private static void analyzeKeywordPatterns(Program program, AntiDebugConfig config, Consumer<String> logger, TaskMonitor monitor, List<Finding> findings) throws CancelledException {
        Listing listing = program.getListing();
        Memory memory = program.getMemory();
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        FunctionManager functionManager = program.getFunctionManager();

        logger.accept("\n--- Searching for Keyword Patterns ---");
        int groupsFoundCount = 0;

        // Optimization: Pre-filter groups to avoid checking disabled ones repeatedly? Not strictly needed yet.

        // Iterate through all executable code units
        AddressSetView addresses = memory.getExecuteSet();
        if (addresses.isEmpty()) {
            logger.accept("No executable memory regions found to scan for keyword patterns.");
            return;
        }
        CodeUnitIterator codeUnits = listing.getCodeUnits(addresses, true);
        Map<Address, List<AntiDebugConfig.KeywordGroup>> primaryKeywordHits = new LinkedHashMap<>();

        // Pass 1: Find all primary keywords
        logger.accept("Scanning for primary keywords...");
        monitor.setMessage("Scanning for primary keywords...");
        monitor.initialize(addresses.getNumAddresses()); // Progress based on addresses
        long progress = 0;
        while (codeUnits.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = codeUnits.next();
            monitor.setProgress(++progress); // Update progress

            for (AntiDebugConfig.KeywordGroup group : config.getKeywordGroups()) {
                monitor.checkCancelled(); // Check inside inner loop too
                String primaryKeyword = group.getPrimaryKeyword(); // Already checked for null/empty in config loading
                if (isKeywordFound(cu, primaryKeyword, program)) {
                    primaryKeywordHits.computeIfAbsent(cu.getAddress(), k -> new ArrayList<>()).add(group);
                    // Don't break here, multiple groups might share the same primary keyword
                }
            }
        }
        logger.accept("Found " + primaryKeywordHits.size() + " potential primary keyword locations.");
        if (monitor.isCancelled()) throw new CancelledException();

        // Pass 2: Search for secondary keywords from primary hits
        logger.accept("Searching for secondary keywords from primary locations...");
        monitor.setMessage("Searching for secondary keywords...");
        monitor.initialize(primaryKeywordHits.size()); // Progress based on primary hits
        progress = 0;

        for (Map.Entry<Address, List<AntiDebugConfig.KeywordGroup>> entry : primaryKeywordHits.entrySet()) {
            monitor.checkCancelled();
            monitor.setProgress(++progress);
            Address primaryAddr = entry.getKey();
            List<AntiDebugConfig.KeywordGroup> potentialGroups = entry.getValue();

            for (AntiDebugConfig.KeywordGroup group : potentialGroups) {
                monitor.checkCancelled(); // Check per group
                monitor.setMessage("Checking group: " + group.getName() + " at " + primaryAddr);

                Function func = functionManager.getFunctionContaining(primaryAddr);
                String funcName = getFunctionName(func);

                if (group.getKeywords().size() == 1) {
                    // Single keyword rule found
                    logger.accept(String.format("Found Single keyword Rule '%s' ('%s') at 0x%s (in function %s)",
                        group.getName(), group.getPrimaryKeyword(), primaryAddr, funcName));

                    // Add Finding
                    findings.add(new Finding(primaryAddr, "Keyword", group.getName(), group.getDescription(), funcName));

                    // Annotate
                    addBookmark(bookmarkManager, primaryAddr, BOOKMARK_CATEGORY_PATTERN + ": " + group.getName(), group.getDescription());
                    setPostComment(listing, primaryAddr, group.getName() + ": " + group.getDescription());
                    setBackgroundColor(program, primaryAddr, PATTERN_PRIMARY_COLOR);
                    groupsFoundCount++;
                } else {
                    // Multi-keyword rule
                    Address lastFoundAddr = primaryAddr;
                    boolean allSecondaryFound = true;
                    List<Address> foundAddresses = new ArrayList<>();
                    foundAddresses.add(primaryAddr); // Add primary address

                    for (int i = 1; i < group.getKeywords().size(); i++) {
                        monitor.checkCancelled();
                        String keyword = group.getKeywordByIndex(i);
                        if (keyword == null) { // Should not happen with config validation
                            allSecondaryFound = false;
                            break;
                        }
                        // Start search *after* the last found address
                        Address searchStart = lastFoundAddr.add(1); // Potential AddressOverflowException handled in findKeywordInRange
                        Address nextAddr = findKeywordInRange(program, listing, searchStart, keyword, group.getSearchRange(), monitor);

                        if (nextAddr != null) {
                            lastFoundAddr = nextAddr;
                            foundAddresses.add(nextAddr);
                        } else {
                            allSecondaryFound = false;
                            break; // Missing a keyword in the sequence
                        }
                    }

                    if (allSecondaryFound) {
                        logger.accept(String.format("Found Keyword group '%s' starting at 0x%s (in function %s)",
                            group.getName(), primaryAddr, funcName));
                        for(int i=0; i<foundAddresses.size(); i++){
                             logger.accept(String.format("  - Keyword '%s' found at 0x%s", group.getKeywordByIndex(i), foundAddresses.get(i)));
                        }

                        // Add Finding for the group start
                        findings.add(new Finding(primaryAddr, "Keyword Group", group.getName(), group.getDescription(), funcName));

                        // Annotate primary keyword
                        addBookmark(bookmarkManager, primaryAddr, BOOKMARK_CATEGORY_PATTERN + ": " + group.getName(), group.getDescription());
                        setPostComment(listing, primaryAddr, group.getName() + ": " + group.getDescription());
                        setBackgroundColor(program, primaryAddr, PATTERN_PRIMARY_COLOR);

                        // Annotate secondary keywords
                        for (int i = 1; i < foundAddresses.size(); i++) {
                             addBookmark(bookmarkManager, foundAddresses.get(i), BOOKMARK_CATEGORY_PATTERN_PART + ": " + group.getName(), "Keyword: " + group.getKeywordByIndex(i));
                             setBackgroundColor(program, foundAddresses.get(i), PATTERN_SECONDARY_COLOR);
                        }
                        groupsFoundCount++;
                    }
                    // TODO: Implement cross-reference search as an alternative if direct search fails.
                }
            } // end loop through potential groups for this address
        } // end loop through primary hits

        logger.accept("Keyword pattern search finished. Found " + groupsFoundCount + " matching groups/rules.");
    }

    /** Analyzes specific instructions based on the configuration. (Placeholder) */
    private static void analyzeInstructions(Program program, AntiDebugConfig config, Consumer<String> logger, TaskMonitor monitor, List<Finding> findings) throws CancelledException {
        if (config.getInstructions().isEmpty()) return; // Skip if no instructions configured

        logger.accept("\n--- Searching for Instructions ---");
        Listing listing = program.getListing();
        InstructionIterator instructions = listing.getInstructions(true);
        int foundCount = 0;

        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            String mnemonic = instruction.getMnemonicString().toLowerCase();

            for (String targetMnemonic : config.getInstructions()) {
                if (mnemonic.equals(targetMnemonic.toLowerCase())) {
                    Address addr = instruction.getAddress();
                    Function func = listing.getFunctionContaining(addr);
                    String funcName = getFunctionName(func);
                    String description = config.getRuleDescription(targetMnemonic); // Assuming description key matches mnemonic

                    logger.accept(String.format("Found instruction '%s' at 0x%s (in function %s)",
                            instruction.toString(), addr, funcName));

                    // Add Finding
                    findings.add(new Finding(addr, "Instruction", targetMnemonic, description, funcName));

                    // Annotate
                    addBookmark(program.getBookmarkManager(), addr, BOOKMARK_CATEGORY_INSTRUCTION, targetMnemonic + " - " + description);
                    setBackgroundColor(program, addr, PATTERN_PRIMARY_COLOR); // Reuse color for now
                    foundCount++;
                    break; // Move to next instruction
                }
            }
        }
        logger.accept("Instruction search finished. Found " + foundCount + " matches.");
    }

    /** Analyzes byte sequences based on the configuration. (Placeholder) */
    private static void analyzeBytes(Program program, AntiDebugConfig config, Consumer<String> logger, TaskMonitor monitor, List<Finding> findings) throws CancelledException {
        if (config.getByteSequences().isEmpty()) return; // Skip if no byte sequences configured

        logger.accept("\n--- Searching for Byte Sequences ---");
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        int foundCount = 0;

        for (String byteSequenceHex : config.getByteSequences()) {
             monitor.checkCancelled();
             monitor.setMessage("Bytes: " + byteSequenceHex);
             byte[] searchBytes;
             try {
                 searchBytes = NumericUtilities.convertHexStringToBytes(byteSequenceHex.replaceAll("\\s", "")); // Remove spaces
                 if (searchBytes.length == 0) {
                     Msg.warn(AntiDebugAnalysisCore.class, "Empty byte sequence configured: " + byteSequenceHex);
                     continue;
                 }
             } catch (NumberFormatException e) {
                 Msg.error(AntiDebugAnalysisCore.class, "Invalid hex string in config: " + byteSequenceHex, e);
                 continue; // Skip invalid sequence
             }

             Address startAddr = program.getMinAddress();
             while (startAddr != null && !monitor.isCancelled()) {
                 Address foundAddr = memory.findBytes(startAddr, searchBytes, null, true, monitor);
                 if (foundAddr == null) {
                     break; // No more occurrences found
                 }

                 Function func = listing.getFunctionContaining(foundAddr);
                 String funcName = getFunctionName(func);
                 String description = config.getRuleDescription(byteSequenceHex); // Assuming description key matches hex string

                 logger.accept(String.format("Found byte sequence '%s' at 0x%s (in function %s)",
                         byteSequenceHex, foundAddr, funcName));

                 // Add Finding
                 findings.add(new Finding(foundAddr, "Bytes", byteSequenceHex, description, funcName));

                 // Annotate
                 addBookmark(program.getBookmarkManager(), foundAddr, BOOKMARK_CATEGORY_BYTES, byteSequenceHex + " - " + description);
                 setBackgroundColor(program, foundAddr, PATTERN_PRIMARY_COLOR); // Reuse color
                 foundCount++;

                 // Prepare for next search
                 try {
                    startAddr = foundAddr.addNoWrap(1);
                 } catch (AddressOverflowException e) {
                     startAddr = null; // Stop searching if we overflow
                 }
             } // end while occurrences
        } // end for each sequence
        logger.accept("Byte sequence search finished. Found " + foundCount + " matches.");
    }


    // =====================================================================================
    // Keyword Searching Helpers
    // =====================================================================================

    /** Checks if a keyword is found in a CodeUnit (Instruction or Label). */
    private static boolean isKeywordFound(CodeUnit cu, String keyword, Program program) {
        if (cu == null || keyword == null || keyword.isEmpty()) {
            return false;
        }
        // Search in Instructions (Mnemonic and Operands)
        if (searchInInstructions(cu, keyword, program)) {
            return true;
        }
        // Search in Labels at the CodeUnit's address
        return searchInLabels(cu.getAddress(), keyword, program);
    }

    /** Searches within an instruction's mnemonic and operands. */
    private static boolean searchInInstructions(CodeUnit cu, String keyword, Program program) {
        if (!(cu instanceof Instruction ins)) { // Java 16+ pattern matching
            return false;
        }

        // Check Mnemonic (Case-insensitive)
        if (ins.getMnemonicString().equalsIgnoreCase(keyword)) {
            return true;
        }

        // Check Operands
        for (int i = 0; i < ins.getNumOperands(); i++) {
            // Check simple string representation first (Case-insensitive for non-hex)
            String opRep = ins.getDefaultOperandRepresentation(i);
            boolean keywordIsHex = keyword.toLowerCase().startsWith("0x");

            if (opRep != null) {
                 if (keywordIsHex) {
                     // Exact match for hex values (case-insensitive hex)
                     if (opRep.equalsIgnoreCase(keyword)) return true;
                 } else {
                     // Contains check for non-hex (case-insensitive)
                     if (opRep.toLowerCase().contains(keyword.toLowerCase())) return true;
                 }
            }

            // Check underlying operand objects (Symbols, Scalars)
            Object[] opObjects = ins.getOpObjects(i);
            for (Object operand : opObjects) {
                if (operand instanceof Address addr) { // Pattern matching
                    // Check symbols at the operand address
                    Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
                    for (Symbol symbol : symbols) {
                        if (symbol.getName().contains(keyword)) { // Symbol names might be case-sensitive
                            return true;
                        }
                    }
                } else if (operand instanceof Scalar scalar) { // Pattern matching
                    // Check scalar value (match hex case-insensitively)
                    String scalarHex = "0x" + Long.toHexString(scalar.getUnsignedValue());
                     if (keywordIsHex && scalarHex.equalsIgnoreCase(keyword)) {
                        return true;
                    }
                    // Optional: Check decimal representation if keyword is numeric but not hex
                    // if (!keywordIsHex && Character.isDigit(keyword.charAt(0))) {
                    //    try {
                    //        long keyVal = Long.parseLong(keyword);
                    //        if (scalar.getValue() == keyVal) return true;
                    //    } catch (NumberFormatException e) { /* Ignore if keyword not decimal */ }
                    // }
                }
            }
        }
        return false;
    }

    /** Searches for the keyword in labels at the given address. */
    private static boolean searchInLabels(Address address, String keyword, Program program) {
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol[] symbols = symbolTable.getSymbols(address);
        for (Symbol symbol : symbols) {
            // Case-insensitive label matching might be desirable
            if (symbol.getName().toLowerCase().contains(keyword.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

     /**
      * Finds the *first* occurrence of the keyword within the specified range,
      * starting the search *strictly after* the startAddress.
      *
      * @param program      The current program.
      * @param listing      The program listing.
      * @param startAddress The address *after* which to start searching.
      * @param keyword      The keyword to find.
      * @param range        The maximum number of bytes to search forward.
      * @param monitor      The task monitor.
      * @return The address of the first occurrence, or null if not found or error occurs.
      * @throws CancelledException If cancelled.
      */
    private static Address findKeywordInRange(Program program, Listing listing, Address startAddress, String keyword, int range, TaskMonitor monitor) throws CancelledException {
        if (startAddress == null || keyword == null || keyword.isEmpty() || range <= 0) {
            return null;
        }

        Address currentAddr = startAddress; // Start searching from the address *after* the previous hit
        Address maxSearchAddr;
        Address maxProgAddr = program.getMaxAddress();

        try {
            // Calculate the maximum address to search, preventing overflow
            maxSearchAddr = startAddress.addNoWrap(range - 1); // range includes the start byte, so add range-1
             if (maxSearchAddr.compareTo(maxProgAddr) > 0) {
                maxSearchAddr = maxProgAddr;
            }
        } catch (AddressOverflowException e) {
            maxSearchAddr = maxProgAddr; // Search till the end if range calculation overflows
        }

        // Iterate through code units in the calculated range
        AddressSet searchSet = new AddressSet(startAddress, maxSearchAddr);
        CodeUnitIterator codeUnits = listing.getCodeUnits(searchSet, true); // Forward search

        while (codeUnits.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = codeUnits.next();
            if (isKeywordFound(cu, keyword, program)) {
                return cu.getAddress(); // Found it
            }
        }

        return null; // Not found within the range
    }


    // =====================================================================================
    // Annotation Utilities
    // =====================================================================================

    /** Adds a bookmark with category and comment. */
    private static void addBookmark(BookmarkManager bookmarkManager, Address addr, String category, String comment) {
        if (bookmarkManager == null || addr == null || category == null || comment == null) return;
        // Avoid overly long comments if necessary, Ghidra might truncate anyway
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
                String newComment = (existing == null || existing.isBlank()) ? comment : existing + "\n" + comment;
                // Avoid duplicate comments if run multiple times
                if (existing == null || !existing.contains(comment)) {
                    cu.setComment(CodeUnit.PRE_COMMENT, newComment.trim());
                }
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
                String newComment = (existing == null || existing.isBlank()) ? comment : existing + "\n" + comment;
                 if (existing == null || !existing.contains(comment)) {
                    cu.setComment(CodeUnit.POST_COMMENT, newComment.trim());
                 }
            }
         } catch (Exception e) {
             Msg.error(AntiDebugAnalysisCore.class, "Error setting post-comment at " + address + ": " + e.getMessage(), e);
         }
    }

    /** Sets the background color for a given address range (typically single address). */
    private static void setBackgroundColor(Program program, Address address, Color color) {
        if (program == null || address == null || color == null) return;
         try {
             BackgroundColorModel colorModel = program.getBackgroundColorModel();
             if (colorModel != null) {
                  colorModel.setBackgroundColor(address, address, color);
             } else {
                 Msg.warn(AntiDebugAnalysisCore.class, "BackgroundColorModel service not available.");
             }
         } catch (Exception e) {
             Msg.error(AntiDebugAnalysisCore.class, "Error setting background color at " + address + ": " + e.getMessage(), e);
         }
    }

    /** Safely gets the function name or "N/A". */
    private static String getFunctionName(Function func) {
        return (func != null) ? func.getName(true) : "N/A"; // Include namespace
    }


    // =====================================================================================
    // CSV Result Writer (New Feature)
    // =====================================================================================
    private static class CsvResultWriter {

        private static final String CSV_HEADER = "Address,Type,RuleName,FunctionContext,Description";

        /**
         * Writes the list of findings to a CSV file.
         * Creates parent directories if they don't exist.
         * Overwrites the file if it already exists.
         *
         * @param outputPath The path to the output CSV file.
         * @param findings The list of findings to write.
         * @throws IOException If an I/O error occurs during writing.
         */
        public static void writeResults(Path outputPath, List<Finding> findings) throws IOException {
            Objects.requireNonNull(outputPath, "CSV output path cannot be null");
            Objects.requireNonNull(findings, "Findings list cannot be null");

            // Create parent directories if needed
            Path parentDir = outputPath.getParent();
            if (parentDir != null && !Files.exists(parentDir)) {
                Files.createDirectories(parentDir);
                Msg.info(CsvResultWriter.class, "Created directory for CSV output: " + parentDir);
            }

            try (PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(outputPath.toFile())))) {
                // Write Header
                writer.println(CSV_HEADER);

                // Write Data Rows
                for (Finding finding : findings) {
                    writer.println(formatCsvRow(finding));
                }
                writer.flush(); // Ensure data is written
            }
            // Catch specific IO exceptions if needed for finer control
        }

        /** Formats a Finding object into a CSV-safe string row. */
        private static String formatCsvRow(Finding finding) {
            return String.join(",",
                quoteCsv(finding.address().toString()), // Address usually doesn't need quoting, but be safe
                quoteCsv(finding.type()),
                quoteCsv(finding.ruleName()),
                quoteCsv(finding.functionContext()),
                quoteCsv(finding.description())
            );
        }

        /** Quotes a string for CSV, handling commas, quotes, and newlines. */
        private static String quoteCsv(String value) {
            if (value == null) {
                return "\"\"";
            }
            // Basic CSV quoting: escape double quotes and wrap in double quotes if necessary
            String escapedValue = value.replace("\"", "\"\"");
            if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
                return "\"" + escapedValue + "\"";
            }
            return escapedValue; // No quoting needed
        }
    }
}
