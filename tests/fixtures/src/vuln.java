public class Vuln {
  void run(String user, String userScript, String input) throws Exception {
    Runtime.getRuntime().exec("ping " + user);
    ProcessBuilder pb = new ProcessBuilder(user);
    new Yaml().load(input);
    new ScriptEngineManager().getEngineByName("js").eval(userScript);
  }
}
