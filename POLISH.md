# TrainFlow UI/UX Polish Plan

## PHASE 1 — DESIGN SYSTEM TOKENS

To ensure the "interface disappears," we will consolidate the current variable-heavy CSS into a strict, predictable Design System.

### COLOR PALETTE (Strict 12)
*   **Surface (Canvas):** `#fafaf9` (Primary background)
*   **Surface (Card):** `#ffffff` (Elevated elements)
*   **Surface (Muted):** `#f5f4f2` (Secondary backgrounds/hover)
*   **Brand (Primary):** `var(--brand-1)` (Dynamic - defaults to #2563eb)
*   **Brand (Secondary):** `var(--brand-2)` (Dynamic - defaults to #1d4ed8)
*   **Text (Strong):** `#1a1917` (Headings, primary labels)
*   **Text (Body):** `#44403c` (Standard reading text)
*   **Text (Muted):** `#78716c` (Meta data, placeholders)
*   **Status (Pass):** `#15803d`
*   **Status (Fail):** `#b91c1c`
*   **Status (Warn):** `#b45309`
*   **Status (Info):** `#2563eb`

### TYPOGRAPHY
*   **Display (Headings):** 'Cormorant Garamond', Serif. `line-height: 1.2`. `font-weight: 600`.
*   **Interface (UI):** 'Outfit', Sans-serif. `line-height: 1`. `font-weight: 500/600`.
*   **Reading (Prose):** 'Inter', Sans-serif. `line-height: 1.6`. `font-weight: 400`.

### SPACING (8px Grid)
*   **Scale:** 4px, 8px, 16px, 24px, 32px, 48px, 64px.
*   *Note: Remove 12px, 20px, 40px instances to enforce rhythm.*

### SHAPE & SHADOW
*   **Radius:** `12px` for Cards/Modals, `8px` for Buttons/Inputs.
*   **Shadow:** `0 10px 15px -3px rgba(0,0,0,0.06), 0 4px 6px -2px rgba(0,0,0,0.03)` (Consolidated).

---

## PHASE 2 — SCREEN-BY-SCREEN AUDIT

### 1. Landing / Role Selection
*   **Issue:** Tiles vary in height based on description length.
*   **Fix:** Use flex-1 on descriptions and fixed min-height for titles to ensure alignment. Add "Enter" key support.

### 2. Login Screens (All Roles)
*   **Issue:** No "Forgot Password" path. Layout jumps slightly between roles.
*   **Fix:** Add "Forgot password? Contact your manager" helper text. Standardize the `login-wrap` width across all three login pages.

### 3. Learner: Course Grid & Progress
*   **Issue:** Staggered animation is nice, but "Mandatory" badge color (`--warn`) is too close to "Pass" badge in some lights.
*   **Fix:** Use a stronger blue accent for assignments. Add skeleton loaders for course cards.

### 4. Course Viewer (Learner)
*   **Issue:** Module navigation is a plain list. Hard to see "Current" vs "Completed" at a glance.
*   **Fix:** Add checkmark icons to `mod-item` for completed modules. Use a "current" indicator bar on the left.

### 5. Quiz Engine
*   **Issue:** Instant feedback is good, but "Shake" and "Pulse" are too fast.
*   **Fix:** Slow down animations by 50ms. Add a subtle background color shift to the whole `quiz-wrap` on result.

### 6. Admin: Dashboard
*   **Issue:** "Trouble Spots" and "Learner Activity" tables look different.
*   **Fix:** Standardize `table-wrap` and `thead` styles. Add "Empty State" illustrations for Trouble Spots.

### 7. Admin: Learners & Teams
*   **Issue:** Tables lack pagination (scaling risk). Search bar is floating without a clear card container.
*   **Fix:** Group search + filters into a single `card-sm`. Implement 50-item pagination.

### 8. Admin: Importer
*   **Issue:** Step indicator dots are small.
*   **Fix:** Increase dot size to 32px. Add "Review" phase where users can edit AI-generated questions before saving.

---

## PHASE 3 — COMPONENT INVENTORY

| Component | Status | Required Action |
| :--- | :--- | :--- |
| **Skeleton Loaders** | Missing | Build `skeleton-card` and `skeleton-row` CSS. |
| **Empty States** | Partial | Add SVG illustrations for "No Courses", "No Members", "No Stats". |
| **Action Toasts** | Complete | Standardize auto-dismiss timeout to exactly 3.2s. |
| **Confirm Dialogs** | Missing | Replace browser `confirm()` with a Soft UI modal. |
| **Focus Trap** | Missing | Add JS logic to trap Tab in modals. |
| **Clickable Rows** | Missing | Make entire table rows clickable where actions exist. |

---

## PHASE 4 — PRIORITY EXECUTION PLAN

1.  **P1 (Blocking)** | **Pagination:** Add pagination to the Admin Learners list. High data volume will crash the DOM. (M)
2.  **P1 (Blocking)** | **A11y:** Replace `div onclick` with `<button>` or add `role="button"` + `tabindex="0"` for keyboard users. (M)
3.  **P2 (High)** | **Loading States:** Implement Skeleton Screen loaders for all async grid/table fetches. (M)
4.  **P2 (High)** | **Focus Management:** Implement focus trapping for all overlays. (S)
5.  **P2 (High)** | **Standardize Spacing:** Audit and fix all non-8px spacing violations in `style.css`. (S)
6.  **P3 (Medium)** | **Empty States:** Add intentional empty states with illustrations for all lists. (M)
7.  **P3 (Medium)** | **Custom Confirm:** Replace native `confirm()` with a styled modal component. (S)
8.  **P3 (Medium)** | **Importer Integration:** Move `importer.html` logic into a `.page` in the main SPA. (L)
9.  **P4 (Low)** | **Row Interaction:** Make table rows hoverable and clickable for primary actions. (S)
10. **P4 (Low)** | **Micro-interactions:** Add 0.1s hover transitions to all icons and chips. (S)

---

## FINAL VERDICT

**Design System:** We are moving to a strict 8px grid with a consolidated 12-color palette. Typography will be streamlined to three functional levels (Display, UI, Prose) to improve readability.

**Top 10 UX Fixes:** Our priority is removing the "fragility" of the UI by adding pagination, loading skeletons, and focus management. We are also bridging the gap between roles with standardized layouts and better affordances (like clickable table rows).

**Overall Verdict:** The foundation is excellent, but the application currently feels like a "developer tool" rather than a "polished product." By enforcing the strict Design System tokens and adding the missing feedback loops (loading/empty states), we will transform TrainFlow into a production-ready, premium LMS.
