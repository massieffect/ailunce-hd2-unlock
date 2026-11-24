import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;

public class FindBeep extends GhidraScript {
  public void run() throws Exception {
    FunctionManager fm = currentProgram.getFunctionManager();
    Listing listing = currentProgram.getListing();
    DecompInterface dec = new DecompInterface();
    dec.openProgram(currentProgram);
    ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

    String[] targets = {"Hal_BeepPlay","beep Phase/Period","beepType=","BeepOut:","Beep End:","Key Beep On","Beep1234"};
    Set<Function> beepFuncs = new LinkedHashSet<>();
    DataIterator di = listing.getDefinedData(true);
    while (di.hasNext()) {
      Data data = di.next();
      Object v = data.getValue();
      if (v instanceof String) {
        String s = (String)v;
        for (String t: targets) {
          if (s.contains(t)) {
            Reference[] refs = getReferencesTo(data.getAddress());
            for (Reference r: refs) {
              Function f = fm.getFunctionContaining(r.getFromAddress());
              if (f!=null) { beepFuncs.add(f);
                println("STR \""+t+"\" @"+data.getAddress()+" used by FUNC "+f.getName()+" @"+f.getEntryPoint()); }
            }
          }
        }
      }
    }
    println("\n===== CALLERS OF EACH BEEP FUNCTION =====");
    for (Function f: beepFuncs) {
      Set<Function> callers = f.getCallingFunctions(mon);
      StringBuilder sb=new StringBuilder();
      for (Function c: callers) sb.append(c.getName()+"@"+c.getEntryPoint()+"  ");
      println("FUNC "+f.getName()+" @"+f.getEntryPoint()+"  <-- "+sb);
    }
    println("\n===== DECOMPILED BEEP FUNCS =====");
    int n=0;
    for (Function f: beepFuncs) {
      if (n++>=5) break;
      DecompileResults res = dec.decompileFunction(f, 60, mon);
      if (res!=null && res.getDecompiledFunction()!=null) {
        String c = res.getDecompiledFunction().getC();
        println("//// "+f.getName()+" @"+f.getEntryPoint()+" ////");
        println(c.length()>2200? c.substring(0,2200): c);
      }
    }
  }
}
