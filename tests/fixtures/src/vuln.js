const cp = require('child_process');
function run(user) { return cp.exec(`ping ${user}`); }
function runSync(user) { return cp.execSync('ping ' + user); }
function ev(expr) { return eval(expr); }
function fn(body) { return new Function(body)(); }
