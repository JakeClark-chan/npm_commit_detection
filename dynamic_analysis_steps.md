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
