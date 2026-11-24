import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
public class DecompAll extends GhidraScript {
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    PrintWriter pw=new PrintWriter(new FileWriter("./alldecomp.c"));
    int n=0;
    for(Function f: fm.getFunctions(true)){
      DecompileResults r=dec.decompileFunction(f,45,mon);
      if(r!=null&&r.getDecompiledFunction()!=null){
        pw.println("//=== FUNC "+f.getName()+" @"+f.getEntryPoint()+" ===");
        pw.println(r.getDecompiledFunction().getC());
        n++;
      }
    }
    pw.close();
    println("DA> decompiled "+n+" functions to alldecomp.c");
  }
}
