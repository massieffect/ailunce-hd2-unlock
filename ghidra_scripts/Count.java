import ghidra.app.script.GhidraScript;
public class Count extends GhidraScript {
  public void run() throws Exception {
    println("CNT> functions: "+currentProgram.getFunctionManager().getFunctionCount());
    println("CNT> language: "+currentProgram.getLanguageID());
    println("CNT> imagebase: "+currentProgram.getImageBase());
  }
}
