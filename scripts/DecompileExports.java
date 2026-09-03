/* Ghidra headless postscript: decompile all exported entry points. */
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileExports extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        SymbolTable st = currentProgram.getSymbolTable();
        int n = 0;
        for (Symbol s : st.getAllSymbols(true)) {
            if (!s.isExternalEntryPoint()) {
                continue;
            }
            Function f = getFunctionContaining(s.getAddress());
            if (f == null) {
                f = getFunctionAt(s.getAddress());
            }
            println("=== " + s.getName() + " @ " + s.getAddress() + " ===");
            if (f != null) {
                DecompileResults r = di.decompileFunction(f, 90, mon);
                if (r.decompileCompleted()) {
                    println(r.getDecompiledFunction().getC());
                } else {
                    println("(decompile failed: " + r.getErrorMessage() + ")");
                }
            } else {
                println("(no function)");
            }
            n++;
        }
        println("DECOMPILED " + n + " entry points");
    }
}
