import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;

public class FindBeep2 extends GhidraScript {
  public void run() throws Exception {
    FunctionManager fm = currentProgram.getFunctionManager();
    Listing listing = currentProgram.getListing();
    Memory mem = currentProgram.getMemory();
    println("existing functions: "+fm.getFunctionCount());

    // locate key beep strings by bytes
    String[] names={"Hal_BeepPlay playCycles","--------------beepType=%d","beep Phase/Period","BeepOut: %d - %d"};
    List<Address> strAddrs=new ArrayList<>();
    for (String s: names){
      Address a=find(null, s.getBytes());
      println("string '"+s+"' @ "+a);
      if(a!=null) strAddrs.add(a);
    }
    // references to those strings (works if code disassembled+analyzed)
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    Set<Function> bf=new LinkedHashSet<>();
    for (Address a: strAddrs){
      ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(a);
      int c=0;
      for (Reference r: ri){ c++;
        Function f=fm.getFunctionContaining(r.getFromAddress());
        println("  ref to "+a+" from "+r.getFromAddress()+" func="+(f!=null?f.getName()+"@"+f.getEntryPoint():"<none>"));
        if(f!=null) bf.add(f);
      }
      if(c==0) println("  (no references found to "+a+")");
    }
    println("\n==== callers of beep funcs ====");
    for (Function f: bf){
      StringBuilder sb=new StringBuilder();
      for (Function c: f.getCallingFunctions(mon)) sb.append(c.getName()+"@"+c.getEntryPoint()+" ");
      println("FUNC "+f.getName()+"@"+f.getEntryPoint()+" <- "+sb);
    }
    println("\n==== decompiled ====");
    int n=0;
    for (Function f: bf){ if(n++>=4) break;
      DecompileResults res=dec.decompileFunction(f,60,mon);
      if(res!=null&&res.getDecompiledFunction()!=null){
        String c=res.getDecompiledFunction().getC();
        println("//// "+f.getName()+"@"+f.getEntryPoint()+" ////");
        println(c.length()>2600?c.substring(0,2600):c);
      }
    }
  }
}
