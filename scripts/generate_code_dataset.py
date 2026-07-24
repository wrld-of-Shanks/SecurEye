import csv
import random

def generate_sql_injection_samples(n=200):
    samples = []
    templates = [
        'const query = "SELECT * FROM users WHERE id = " + userId;',
        'db.execute("SELECT * FROM products WHERE name = \'" + search + "\'");',
        'const sql = `SELECT * FROM orders WHERE user_id = ${req.body.user_id}`;',
        'string q = "DELETE FROM accounts WHERE id=" + accountId;',
        'query = "INSERT INTO logs (msg) VALUES (\'" + message + "\')";',
        'const update = "UPDATE users SET name=\'" + newName + "\' WHERE id=" + id;',
        'sql = "SELECT * FROM users WHERE username=\'" + username + "\' AND password=\'" + pass + "\'";',
        'db.query("SELECT * FROM products WHERE category=" + category);',
        'const deleteQuery = "DELETE FROM cart WHERE user_id=" + userId;',
        'execute("UPDATE accounts SET balance=balance-" + amount + " WHERE id=" + id);'
    ]
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'sql_injection'))
    return samples

def generate_xss_samples(n=200):
    samples = []
    templates = [
        'element.innerHTML = userInput;',
        'document.write("<div>" + data + "</div>");',
        'div.outerHTML = req.body.content;',
        'element.insertAdjacentHTML("beforeend", userContent);',
        'response.send(`<p>${comment}</p>`);',
        'el.innerHTML = "<img src=\'" + url + "\'>";',
        'document.body.innerHTML += userData;',
        'output.innerHTML = "<a href=\'" + link + "\'>" + text + "</a>";',
        'element.innerHTML = "<script>" + script + "</script>";',
        'container.insertAdjacentHTML("afterend", req.query.html);'
    ]
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'xss'))
    return samples

def generate_hardcoded_credentials_samples(n=200):
    samples = []
    templates = [
        'const password = "admin123";',
        'const API_KEY = "sk-1234567890abcdef";',
        'DB_PASSWORD = "secret_pass_123";',
        'const SECRET = "mysecretkey";',
        'api_token = "ghp_ABCDEFGHIJKLMNOP";',
        'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";',
        'password: "root",',
        'const dbPass = "mysql_password";',
        'TOKEN = "eyJhbGciOiJIUzI1NiJ9";',
        'const secret_key = "supersecret";'
    ]
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'hardcoded_credentials'))
    return samples

def generate_command_injection_samples(n=200):
    samples = []
    templates = [
        'exec("cat " + filename);',
        'system("ping " + host);',
        'child_process.exec(`ls ${dir}`);',
        'os.system("curl " + url);',
        'exec("rm -rf " + path);',
        'popen("grep " + pattern + " " + file);',
        'subprocess.call("python " + script);',
        'child_process.execSync("npm install " + pkg);',
        'exec("tar -xvf " + archive);',
        'system("nslookup " + userInput);'
    ]
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'command_injection'))
    return samples

def generate_path_traversal_samples(n=200):
    samples = []
    templates = [
        'readFile("/data/" + userPath);',
        'fs.readFileSync(baseDir + "/" + filename);',
        'open("/uploads/" + req.params.file);',
        'const content = fs.readFile(path.join(dir, userInput));',
        'readfile("/etc/" + configFile);',
        'fs.readFile("/var/www/" + userFile, callback);',
        'const data = readFileSync("/opt/" + fileName);',
        'open("/backup/" + req.body.filename);',
        'fs.readFileSync("/logs/" + logFile);',
        'readFile(config.basePath + "/" + req.query.path);'
    ]
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'path_traversal'))
    return samples

def generate_not_vulnerable_samples(n=300):
    samples = []
    templates = [
        'const x = 5;',
        'function add(a, b) { return a + b; }',
        'const arr = [1, 2, 3, 4, 5];',
        'if (x > 0) { console.log("positive"); }',
        'for (let i = 0; i < 10; i++) { sum += i; }',
        'const result = arr.map(x => x * 2);',
        'export default function myFunc() {}',
        'class MyClass { constructor() { this.x = 0; } }',
        'try { doSomething(); } catch (e) { log(e); }',
        'const data = await fetch(url);',
        'module.exports = { helper: () => {} };',
        'import React from "react";',
        'const [state, setState] = useState(0);',
        'app.get("/api", (req, res) => { res.json({}); });',
        'const config = require("./config");',
        'setTimeout(() => {}, 1000);',
        'Promise.all([p1, p2]).then(r => {});',
        'Object.assign(target, source);',
        'const merged = {...obj1, ...obj2};',
        'console.log("debug");'
    ]
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'not_vulnerable'))
    return samples

def main():
    all_samples = []
    all_samples.extend(generate_sql_injection_samples(200))
    all_samples.extend(generate_xss_samples(200))
    all_samples.extend(generate_hardcoded_credentials_samples(200))
    all_samples.extend(generate_command_injection_samples(200))
    all_samples.extend(generate_path_traversal_samples(200))
    all_samples.extend(generate_not_vulnerable_samples(300))
    
    random.shuffle(all_samples)
    
    output_path = '/Users/shanks/Desktop/SentinelAI/data/code/cve_dataset.csv'
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['code', 'label'])
        writer.writerows(all_samples)
    
    print(f"Generated {len(all_samples)} samples")
    print(f"Saved to {output_path}")
    
    from collections import Counter
    labels = [s[1] for s in all_samples]
    print("\nClass distribution:")
    for label, count in Counter(labels).items():
        print(f"  {label}: {count}")

if __name__ == '__main__':
    main()
