TODO:
+ Validate with Synk SAST
+ Add FALCO_TOKEN authorization header to requests, using crypto.timingSafeEqual to avoid timing attacks on comparing tokens before bringing server into use publicly.

Package Hunter:
+ Setup vagrant and virtualbox using apt
+ git clone https://github.com/SeaW1nd/Package-Hunter.git
+ cd Package-Hunter
+ sudo modprobe -r kvm_intel
+ vagrant up -> Download box and ensure that there is no VM inside VB
+ vagrant ssh
    + cd /vagrant
    + npm ci
    + check both docker and falco
    + cd falco (pwd: /vagrant/falco)
    + docker build -t maldep .
    + create .htrrc if not present
    + Add token auth to src/server.js:
        ```javascript
        const REQUIRED_TOKEN = process.env.FALCO_TOKEN
        app.use((req, res, next) => {
          if (!REQUIRED_TOKEN) {
            debug('FALCO_TOKEN is not configured')
            return res.status(500).send('Server token not configured')
          }
          const authHeader = req.get('Authorization') || ''
          const token = authHeader.replace(/^Bearer\s+/i, '')
          if (token !== REQUIRED_TOKEN) {
            debug('Unauthorized request blocked')
            return res.status(401).send('Unauthorized')
          }
          next()
        })
        ```
    + sudo systemctl restart falco
    + sudo systemctl status falco
    + FALCO_TOKEN=your-secret NODE_ENV=development DEBUG=pkgs* node src/server.js

Inside repo:
+ Use dynamic_analysis.py:
    ```bash
    FALCO_TOKEN=your-secret python dynamic_analysis.py /path/to/repo <commit-hash>
    # Optional: POLL_INTERVAL=2 ANALYSIS_TIMEOUT=300
    ```
+ Manual steps:
    + clone into /tmp and cd repo
    + git checkout <commit-hash>
    + npm pack -> .tgz package
    + curl -v -H 'Content-Type: application/octet-stream' --data-binary @tgz-name http://localhost:3000/monitor/project/npm => get id
    + curl -H 'Authorization: Bearer your-secret' "http://localhost:3000/?id=above-id" -> pending: wait, finished: take result


+ Obfuscate 100 samples then calculate accuracy
+ Report md
+ Verification: commit
+ 100 commits containing 50 safe, 50 unsafe, run how many commits mal.
+ Note obfuscate tool: https://github.com/javascript-obfuscator/javascript-obfuscator

Wait, We will need to check a little bit about obfuscation and deobfuscation. 
* Install obfuscator at `$ npm install --save-dev javascript-obfuscator`
* Use it to obfuscate simple code (for example, a simple function that prints "Hello World")
* Then make a new LLM agent with role is a deobfuscator, check that if commit need to deobfuscate, if yes use de4js tool I provided inside my code, deobfuscate, and try to fix code to meaningful/original code. With that step, inside static analysis you will check if I previously implemented tool usage at static analysis agent, if yes remove it
* Use the new LLM agent to test obfuscated simple code, to check if deobfuscator agent is *like* an original version
