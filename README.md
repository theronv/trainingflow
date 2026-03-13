# TrainFlow 🎓

TrainFlow is a modern, lightweight Learning Management System (LMS) designed for professional teams. It enables organizations to create, manage, and deliver training courses with automated AI-assisted content generation and verifiable PDF certifications.

---

## 🏗️ Architecture

TrainFlow is built as a **decoupled SPA (Single Page Application)** with a serverless backend:

-   **Frontend:** Vanilla JavaScript, HTML5, and CSS3. 
    -   Uses a custom **"Soft UI" Design System** for a premium, corporate aesthetic.
    -   Modularized structure: `index.html` (DOM), `js/app.js` (Logic), `css/style.css` (Styles).
-   **Backend:** [Cloudflare Workers](https://workers.cloudflare.com/) using the [Hono](https://hono.dev/) framework.
-   **Database:** [Turso](https://turso.tech/) (Edge SQLite/libSQL) for low-latency global data access.
-   **AI Engine:** [Google Gemini 2.5 Flash](https://deepmind.google/technologies/gemini/) for automated course summaries and quiz generation.

---

## ✨ Key Features

### 👨‍🎓 Learner Experience
-   **Interactive Modules:** Structured reading followed by "Competency Checks" (Quizzes).
-   **Focus Mode:** Distraction-free reading experience with collapsible navigation.
-   **Verifiable Certificates:** Passing a course generates a styled PDF certificate with a unique `CertID` for verification.
-   **Gamified Feedback:** Staggered animations, haptic quiz feedback (shake/pulse), and celebratory confetti bursts.

### ⚙️ Manager Experience
-   **AI Course Importer:** Drop Markdown files to automatically generate module summaries and multiple-choice questions via Gemini.
-   **Course Builder:** Full-featured UI to manually create and edit modules and quizzes.
-   **Real-time Analytics:** Dashboard tracking total learners, monthly completions, and course-specific pass rates.
-   **White-labeling:** Dynamic branding system to customize colors, logos, and pass thresholds.

---

## 🚀 Getting Started

### Prerequisites
-   [Node.js](https://nodejs.org/) installed.
-   [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-setup/) CLI for Cloudflare Workers.
-   A [Turso](https://turso.tech/) database instance.

### Installation

1.  **Clone the repository** and navigate to the root.
2.  **Configure the Backend:**
    ```bash
    cd worker
    npm install
    # Create .dev.vars for local secrets:
    # TURSO_URL=libsql://your-db.turso.io
    # TURSO_TOKEN=your_token
    # JWT_SECRET=your_secret
    # GEMINI_API_KEY=your_key
    ```
3.  **Initialize the Database:**
    Run the contents of `schema.sql` against your Turso instance.
4.  **Run Locally:**
    ```bash
    # In the worker directory:
    npm run dev
    
    # In the root directory (to serve the frontend):
    npx serve .
    ```

---

## 🛠️ Tech Stack & Utilities

-   **Hono:** Ultra-fast web framework for the Worker.
-   **libSQL Client:** Edge-compatible database driver.
-   **html2canvas & jsPDF:** Client-side PDF generation for certificates.
-   **Canvas-Confetti:** High-performance micro-animations.
-   **Web Crypto API:** PBKDF2 password hashing (no external dependencies).

---

## 🛡️ Security & Polish
-   **JWT Authentication:** Secure role-based access for Learners and Admins.
-   **Hardened Storage:** Robust `sessionStorage` wrappers with `try/catch` fallbacks.
-   **Clean Code:** Decoupled logic, centralized constants, and zero console pollution.
-   **Robustness:** Fixed "O'Brien Bug" (properly escaped single-quotes in UI attributes).

---

## 🧪 Demo Mode
The application includes a **Demo Mode** (offline) that bypasses the backend and uses mock data. This is ideal for testing UI/UX improvements or showing the platform to stakeholders without a database connection. Click **"Try Demo Mode"** on the landing page to activate.
