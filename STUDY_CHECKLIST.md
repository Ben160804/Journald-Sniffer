# FastAPI + Docker — Study Checklist
**Project:** Journald-Sniffer  
**Goal:** Explain every new file and change in an interview  
**Study method:** Go through each item, ask Claude to expand, build intuition before code

---

## Before You Start
- [ ] Read this checklist once end-to-end
- [ ] For each item, ask Claude: "Explain this concept like I'm 5"
- [ ] Do NOT skip items you don't understand — ask Claude for analogies
- [ ] After understanding, verify by explaining it out loud to yourself

---

## Module 1: What is a Web API? (Prerequisite)
**Reference:** https://www.youtube.com/watch?v=GPknoBqgoIY (What is REST API)

- [ ] Understand: HTTP methods (GET vs POST)
- [ ] Understand: request → server → response flow
- [ ] Understand: what a URL path is (`/health`, `/sessions`)
- [ ] Understand: what status codes mean (200, 500, 501)
- [ ] Explain: "Why would a Python script need to become a web service?"

**Checkpoint:** Can you explain, without jargon, why `parser.py` running on CLI is different from exposing it over HTTP?

---

## Module 2: FastAPI Basics
**References:**
- Official tutorial: https://fastapi.tiangolo.com/tutorial/
- "FastAPI in 10 minutes": https://www.youtube.com/watch?v=t6NoibBohHA

- [ ] What is FastAPI? (framework, not a server)
- [ ] What is an "endpoint" / "route"?
- [ ] What does `@app.get("/health")` mean? (decorator pattern)
- [ ] What is FastAPI's `/docs` and why is it useful?
- [ ] What is Pydantic? (validation library)
- [ ] What is a Pydantic `BaseModel`?
- [ ] What does `response_model` do in a decorator?
- [ ] What is the difference between GET and POST in FastAPI?
- [ ] What is `HTTPException` and when do you raise it?

**Practice with Claude:**
- Ask Claude to draw a diagram: "Client → FastAPI → my function → return JSON"
- Ask Claude to show a minimal "hello world" FastAPI app

**Checkpoint:** Can you trace what happens when someone calls `GET /health`?

---

## Module 3: Python Imports and `sys.path`
**References:**
- Python modules: https://docs.python.org/3/tutorial/modules.html
- `sys.path` explained: https://stackoverflow.com/questions/11515944/how-to-use-sys-path-in-python

- [ ] What is a Python module?
- [ ] What is the difference between `import X` and `from X import Y`?
- [ ] What is a package? (folder with `__init__.py`)
- [ ] What is `sys.path`? (module search path)
- [ ] What does `sys.path.insert(0, ...)` do?
- [ ] Why does `from parser import parse_rawlog` fail from repo root?
- [ ] Why does it work inside `fac10sniffer/`?
- [ ] What is the fix and why does it work?

**Practice with Claude:**
- Ask Claude to simulate the import error and show the exact error message
- Ask Claude to explain `__file__` and `os.path.dirname`

**Checkpoint:** Can you explain the `sys.path.insert(0, ...)` line to someone who knows Python basics but has never seen this trick?

---

## Module 4: Your `app.py` — Endpoints Deep Dive
**Reference:** `/home/bigfoot/Journald-Sniffer/app.py`

For EACH endpoint below, understand:
1. What HTTP method is used and why
2. What it calls in your existing pipeline
3. What it returns
4. What errors could happen and how they're handled

- [ ] `GET /health` — purpose, returns, db check logic
- [ ] `POST /ingest` — purpose, why it returns 501 in Docker, `systemd` import guard
- [ ] `POST /parse` — purpose, how it reuses `parse_rawlog()`, LLM call counting
- [ ] `POST /alerts` — purpose, how it reuses watchdog query logic
- [ ] `GET /sessions` — purpose, query params (`src_ip`, `outcome`, `limit`)
- [ ] `GET /raw` — purpose, query params (`program`, `limit`)

**Practice with Claude:**
- Pick each endpoint, paste the function, ask Claude: "Walk me through this line by line"
- Ask Claude: "What happens if the DB is down when someone calls /alerts?"

**Checkpoint:** Can you draw a diagram showing how a request flows through `/parse`?

---

## Module 5: Pydantic Schemas in Your Code
**Reference:** `app.py` lines 19-42

- [ ] What problem does Pydantic solve?
- [ ] What is `BaseModel`?
- [ ] What are field types (`str`, `int`, `Optional[str]`) doing?
- [ ] What does `Optional[str]` mean? (can be str or None)
- [ ] What does `List[dict]` mean?
- [ ] How does FastAPI use these models for request validation?
- [ ] How does FastAPI use these models for response validation?
- [ ] What happens if you return a dict missing a required field?

**Practice with Claude:**
- Ask Claude to show what happens if you send invalid data to a Pydantic-validated endpoint
- Ask Claude: "Show me a Pydantic model for a login request"

**Checkpoint:** Can you explain why `SessionQuery` has `src_ip: Optional[str] = None`?

---

## Module 6: What is Docker?
**References:**
- Docker in 5 minutes: https://www.youtube.com/watch?v=-SkMJglFqmI
- Docker vs VM: https://www.youtube.com/watch?v=6OuD1BRNVQQ

- [ ] What problem does Docker solve?
- [ ] What is a container vs a VM?
- [ ] What is a Docker image?
- [ ] What is a Dockerfile?
- [ ] What is a Docker container?
- [ ] What is a volume? (data persistence)
- [ ] What is a bind mount? (mounting host files into container)
- [ ] What is Docker Compose? (multi-container orchestration)
- [ ] What does `docker compose up` do?
- [ ] What does `docker compose down` do?
- [ ] What does `docker compose down -v` do? (destructive)

**Practice with Claude:**
- Ask Claude to draw: "How does a Dockerfile become a running container?"
- Ask Claude: "Why can't I just run Postgres and my app as two separate Python processes?"

**Checkpoint:** Can you explain Docker to a non-technical person in 30 seconds?

---

## Module 7: Your `Dockerfile` Line by Line
**Reference:** `/home/bigfoot/Journald-Sniffer/Dockerfile`

For EACH line, understand what it does and why:

- [ ] `FROM python:3.11-slim` — base image concept
- [ ] `RUN apt-get update && apt-get install -y --no-install-recommends` — what RUN does
- [ ] `gcc` — why a compiler is needed in a Python image
- [ ] `libsystemd0` — what this library is and why it's needed
- [ ] `rm -rf /var/lib/apt/lists/*` — layer caching and image size
- [ ] `WORKDIR /app` — working directory inside container
- [ ] `COPY requirements.txt .` — why copy requirements first (layer caching)
- [ ] `RUN pip install --no-cache-dir -r requirements.txt` — cache busting
- [ ] `COPY . .` — copy source code
- [ ] `ENV DB_HOST=${DB_HOST:-db}` — env vars and default values
- [ ] `EXPOSE 8000` — documentation vs actual port opening
- [ ] `CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]` — entrypoint

**Practice with Claude:**
- Paste the Dockerfile, ask Claude to explain each instruction as if teaching Docker for the first time
- Ask Claude: "What happens if I remove `COPY requirements.txt .` and just do `COPY . .`?"

**Checkpoint:** Can you explain the layer caching optimization in the Dockerfile?

---

## Module 8: Your `docker-compose.yml` Line by Line
**Reference:** `/home/bigfoot/Journald-Sniffer/docker-compose.yml`

- [ ] `services:` — what is a service?
- [ ] `api:` section — name, build, ports, environment, depends_on
- [ ] `db:` section — image, environment, volumes
- [ ] Port mapping `"8080:8000"` — host:container syntax
- [ ] `depends_on` — what it does and doesn't do (start order vs health check)
- [ ] `volumes:` — named volume for pgdata
- [ ] Bind mount `./db/schema.sql:/docker-entrypoint-initdb.d/schema.sql` — how auto-migration works
- [ ] Why `DB_HOST=db` works (Docker internal DNS)

**Practice with Claude:**
- Ask Claude to draw the network topology: "How does api container talk to db container?"
- Ask Claude: "What's the difference between a named volume and a bind mount?"

**Checkpoint:** Can you trace what happens from `docker compose up` to the API being reachable?

---

## Module 9: The Bug Fixes (Interview Gold)
**References:**
- `db/schema.sql` — added seed row
- `fac10sniffer/parser.py` — added `if __name__ == "__main__":`
- `fac10sniffer/watchdogv2.py` — added `if __name__ == "__main__":`

### Schema seed fix
- [ ] What is `ingest_state` table? (singleton bookmark)
- [ ] Why does `cursor.fetchone()[0]` crash when table is empty?
- [ ] What does the seed row `INSERT INTO ingest_state (id, last_jcursor) VALUES (TRUE, NULL)` do?
- [ ] Why `TRUE` and not `1` or `'true'`? (boolean PK with CHECK constraint)
- [ ] What is the `single_row` CHECK constraint enforcing?

### Import-time execution fix
- [ ] What does Python do when you `import parser`? (runs top-level code)
- [ ] Why is `parse_rawlog()` at line 325 a problem?
- [ ] What is `if __name__ == "__main__":`?
- [ ] What is `__name__`? (module name vs `"__main__"`)
- [ ] Why does wrapping in `if __name__ == "__main__":` fix the crash?
- [ ] Same logic for `watchdogv2.py`

**Practice with Claude:**
- Ask Claude to simulate: "What happens when app.py does `from parser import parse_rawlog` before the fix?"
- Ask Claude: "Show me the exact error message from the crash"

**Checkpoint:** Can you explain BOTH bugs and their fixes without looking at the code?

---

## Module 10: How Deploy to Render Works
**Reference:** https://render.com/docs/deploy-docker

- [ ] What is a "Web Service" on Render?
- [ ] How does Render build a Docker image from your repo?
- [ ] What environment variables do you need to set?
- [ ] What is Render's free tier limits? (spin down after inactivity, 512MB RAM)
- [ ] How do you get a live URL?
- [ ] What happens to the database when the free tier spins down?
- [ ] Why is this still useful for interviews? (it works when you wake it up)

**Practice with Claude:**
- Ask Claude to walk through the Render deploy process step by step
- Ask Claude: "What's the difference between Render's free web service and free PostgreSQL?"

**Checkpoint:** Can you list the exact steps to go from GitHub push to live URL?

---

## Module 11: Interview Defense Scripts
**Goal:** Be able to answer these without hesitation

For EACH question below, write a 30-second answer:

- [ ] "What does your project do?" (1 sentence)
- [ ] "What is the architecture?" (4 components: ingest, parse, LLM, alert)
- [ ] "What is FastAPI and why did you use it?"
- [ ] "What is Docker and why did you containerize?"
- [ ] "What was the hardest bug you fixed?" (import-time execution + schema seed)
- [ ] "How does the LLM layer work?" (Groq API, only called for ambiguous sessions)
- [ ] "What is the detection logic?" (brute force, scan, success-after-failure)
- [ ] "What would you improve if you had more time?" (auth, rate limiting, more detectors)

**Practice with Claude:**
- Paste each question, ask Claude to roleplay as interviewer
- Record yourself answering — listen back

---

## Final Checklist
- [ ] Can explain every file: app.py, Dockerfile, docker-compose.yml, requirements.txt
- [ ] Can explain every bug fix and why it was needed
- [ ] Can draw the architecture from memory
- [ ] Can trace a request from HTTP → response
- [ ] Can explain Docker in 30 seconds to a non-technical person
- [ ] Can explain what happens when Render deploys your repo
- [ ] Have a 30-second answer for each interview question in Module 11
