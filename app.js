/**
 * Scam Spotter - Application Logic & Interactive Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM References
  const messageInput = document.getElementById('messageInput');
  const checkBtn = document.getElementById('checkBtn');
  const clearBtn = document.getElementById('clearBtn');
  const alertBox = document.getElementById('inputAlert');
  const resultsContainer = document.getElementById('resultsContainer');
  const emptyState = document.getElementById('emptyState');
  const sampleChipsContainer = document.getElementById('sampleChips');
  const sampleNote = document.getElementById('sampleNote');
  const themeToggle = document.getElementById('themeToggle');
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const langButtons = document.querySelectorAll('.lang-btn');
  const uploadScreenshotBtn = document.getElementById('uploadScreenshotBtn');
  const screenshotInput = document.getElementById('screenshotInput');
  const imagePreviewArea = document.getElementById('imagePreviewArea');
  const imagePreviewThumb = document.getElementById('imagePreviewThumb');
  const imageFileName = document.getElementById('imageFileName');
  const removeImageBtn = document.getElementById('removeImageBtn');
  const ocrProgressStatus = document.getElementById('ocrProgressStatus');
  const ocrProgressText = document.getElementById('ocrProgressText');
  const ocrProgressBarFill = document.getElementById('ocrProgressBarFill');

  // ROI Calculator DOM References
  const roiOrgType = document.getElementById('roiOrgType');
  const roiScaleInput = document.getElementById('roiScaleInput');
  const roiScaleLabel = document.getElementById('roiScaleLabel');
  const roiCostOut = document.getElementById('roiCostOut');
  const roiSavingsOut = document.getElementById('roiSavingsOut');
  const roiMultiplierOut = document.getElementById('roiMultiplierOut');

  // Rulebook DOM References
  const rulesTableBody = document.getElementById('rulesTableBody');
  const resetWeightsBtn = document.getElementById('resetWeightsBtn');
  const weightsStatus = document.getElementById('weightsStatus');

  // Test Runner DOM
  const testStatsContainer = document.getElementById('testStatsContainer');
  const testListContainer = document.getElementById('testListContainer');

  // Quiz DOM
  const quizBox = document.getElementById('quizBox');

  // State
  let currentAnalysis = null;
  let activeSampleId = null;
  let currentLang = 'en';
  let customWeights = loadWeights();

  // Initialize Theme & Lang
  initTheme();

  // Build Components
  buildSampleChips();
  buildRulebookTable();
  initQuiz();
  runSelfTestCorpus();
  initRoiCalculator();

  // Initial Check if pre-filled
  loadSample('sbi-kyc');

  // Event Listeners
  checkBtn.addEventListener('click', () => runAnalysis(true));
  clearBtn.addEventListener('click', handleClear);

  messageInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runAnalysis(true);
    }
  });

  messageInput.addEventListener('input', () => {
    if (activeSampleId) {
      activeSampleId = null;
      sampleNote.textContent = '';
      document.querySelectorAll('.chip-btn').forEach(c => c.classList.remove('active'));
    }
  });

  resetWeightsBtn.addEventListener('click', handleResetWeights);

  // Language Selector
  langButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      langButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentLang = btn.dataset.lang || 'en';
      if (currentAnalysis) {
        renderResults(currentAnalysis);
      }
    });
  });

  // Screenshot Upload & Paste (OCR Reader)
  if (uploadScreenshotBtn && screenshotInput) {
    uploadScreenshotBtn.addEventListener('click', () => {
      screenshotInput.click();
    });

    screenshotInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) handleImageFile(file);
    });
  }

  if (removeImageBtn) {
    removeImageBtn.addEventListener('click', () => {
      if (imagePreviewArea) imagePreviewArea.hidden = true;
      if (screenshotInput) screenshotInput.value = '';
      if (imagePreviewThumb) imagePreviewThumb.src = '';
    });
  }

  // Handle Ctrl+V paste of images directly into page
  window.addEventListener('paste', (e) => {
    const items = (e.clipboardData || e.originalEvent.clipboardData).items;
    for (let index in items) {
      const item = items[index];
      if (item.kind === 'file' && item.type.startsWith('image/')) {
        const file = item.getAsFile();
        handleImageFile(file);
        break;
      }
    }
  });

  async function handleImageFile(file) {
    if (!file || !file.type.startsWith('image/')) {
      showAlert('Please upload a valid screenshot image file (PNG, JPG, WebP).');
      return;
    }

    // Display image preview card
    if (imagePreviewArea) imagePreviewArea.hidden = false;
    if (imageFileName) imageFileName.textContent = `${file.name} (${Math.round(file.size / 1024)} KB)`;
    if (ocrProgressStatus) ocrProgressStatus.hidden = false;
    if (ocrProgressText) ocrProgressText.textContent = 'Preparing image for text extraction...';
    if (ocrProgressBarFill) ocrProgressBarFill.style.width = '15%';

    const reader = new FileReader();
    reader.onload = (event) => {
      const dataUrl = event.target.result;
      if (imagePreviewThumb) imagePreviewThumb.src = dataUrl;

      const img = new Image();
      img.onload = async () => {
        // High-contrast Canvas Preprocessing for SMS/WhatsApp screenshots
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        let w = img.width;
        let h = img.height;
        const maxDim = 1400;
        if (w > maxDim || h > maxDim) {
          if (w > h) {
            h = Math.round((h * maxDim) / w);
            w = maxDim;
          } else {
            w = Math.round((w * maxDim) / h);
            h = maxDim;
          }
        }
        canvas.width = w;
        canvas.height = h;
        ctx.drawImage(img, 0, 0, w, h);

        // Preprocess pixels: boost contrast so chat bubbles & font edges pop
        try {
          const imgData = ctx.getImageData(0, 0, w, h);
          const d = imgData.data;
          for (let i = 0; i < d.length; i += 4) {
            const gray = (d[i] * 0.299 + d[i + 1] * 0.587 + d[i + 2] * 0.114);
            const contrast = gray > 140 ? 255 : (gray < 80 ? 0 : gray);
            d[i] = contrast;
            d[i + 1] = contrast;
            d[i + 2] = contrast;
          }
          ctx.putImageData(imgData, 0, 0);
        } catch (e) {
          // If security blocks canvas read, continue with standard canvas
        }

        if (ocrProgressText) ocrProgressText.textContent = 'Reading text using OCR engine...';
        if (ocrProgressBarFill) ocrProgressBarFill.style.width = '35%';

        // Try Tesseract OCR
        if (typeof Tesseract !== 'undefined') {
          try {
            const res = await Tesseract.recognize(canvas, 'eng', {
              logger: m => {
                if (m.status === 'recognizing text') {
                  const pct = Math.min(95, Math.round((m.progress || 0) * 100));
                  if (ocrProgressText) ocrProgressText.textContent = `Reading text from screenshot... (${pct}%)`;
                  if (ocrProgressBarFill) ocrProgressBarFill.style.width = `${pct}%`;
                }
              }
            });

            const extracted = (res.data && res.data.text) ? res.data.text.trim() : '';
            if (extracted.length >= 8) {
              messageInput.value = extracted;
              if (ocrProgressStatus) {
                ocrProgressStatus.innerHTML = '<span style="color: var(--risk-low); font-weight: 700;">✓ Text Extracted from Screenshot!</span>';
              }
              if (ocrProgressBarFill) ocrProgressBarFill.style.width = '100%';
              sampleNote.textContent = `Screenshot "${file.name}" scanned. Real text extracted into box.`;
              runAnalysis(true);
              return;
            }
          } catch (tessErr) {
            console.warn('Tesseract OCR error:', tessErr);
          }
        }

        // Friendly fallback if image was blurry or OCR returned minimal text
        if (ocrProgressStatus) {
          ocrProgressStatus.innerHTML = '<span style="color: var(--risk-med); font-weight: 600;">⚠️ Screenshot loaded! Text was faint/stylized. Review image above & type or paste the message/link below.</span>';
        }
        if (ocrProgressBarFill) ocrProgressBarFill.style.width = '100%';
        if (!messageInput.value.trim()) {
          messageInput.placeholder = 'Screenshot loaded above! Type or paste the words / link from the image here...';
        }
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  }

  // Tab Switching
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.dataset.tab;
      tabButtons.forEach(b => b.classList.remove('active'));
      tabContents.forEach(tc => tc.hidden = true);

      btn.classList.add('active');
      const targetEl = document.getElementById(targetTab);
      if (targetEl) targetEl.hidden = false;
    });
  });

  // Theme Toggle
  themeToggle.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 
      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('scamlens-theme', newTheme);
    updateThemeToggleLabel(newTheme);
  });

  function initTheme() {
    const saved = localStorage.getItem('scamlens-theme');
    if (saved) {
      document.documentElement.setAttribute('data-theme', saved);
      updateThemeToggleLabel(saved);
    } else {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      updateThemeToggleLabel(prefersDark ? 'dark' : 'light');
    }
  }

  function updateThemeToggleLabel(theme) {
    themeToggle.innerHTML = theme === 'dark' 
      ? '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg> Light' 
      : '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg> Dark';
  }

  function createSampleScreenshot(title, sender, text, isScam) {
    const canvas = document.createElement('canvas');
    canvas.width = 640;
    canvas.height = 360;
    const ctx = canvas.getContext('2d');

    // Phone dark background
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(0, 0, 640, 360);

    // Chat Header
    ctx.fillStyle = '#1e293b';
    ctx.fillRect(0, 0, 640, 64);

    // Sender title
    ctx.fillStyle = '#f8fafc';
    ctx.font = 'bold 18px sans-serif';
    ctx.fillText(`SMS: ${sender}`, 28, 40);

    // Message Bubble
    ctx.fillStyle = isScam ? '#334155' : '#1e3a8a';
    if (ctx.roundRect) {
      ctx.beginPath();
      ctx.roundRect(24, 88, 592, 240, 12);
      ctx.fill();
    } else {
      ctx.fillRect(24, 88, 592, 240);
    }

    // Message Text
    ctx.fillStyle = '#ffffff';
    ctx.font = '16px sans-serif';
    
    const words = text.split(' ');
    let line = '';
    let y = 130;
    for (let n = 0; n < words.length; n++) {
      const testLine = line + words[n] + ' ';
      const metrics = ctx.measureText(testLine);
      if (metrics.width > 540 && n > 0) {
        ctx.fillText(line, 48, y);
        line = words[n] + ' ';
        y += 28;
      } else {
        line = testLine;
      }
    }
    ctx.fillText(line, 48, y);

    return new Promise(resolve => {
      canvas.toBlob(blob => {
        const file = new File([blob], `${title.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.png`, { type: 'image/png' });
        resolve(file);
      }, 'image/png');
    });
  }

  // Sample Chips Loader
  function buildSampleChips() {
    sampleChipsContainer.innerHTML = '';
    const scamGroup = document.createElement('div');
    scamGroup.className = 'sample-row';
    scamGroup.innerHTML = '<span class="sample-label">Scam Alerts</span>';

    const genuineGroup = document.createElement('div');
    genuineGroup.className = 'sample-row';
    genuineGroup.innerHTML = '<span class="sample-label">Normal Texts</span>';

    const screenshotGroup = document.createElement('div');
    screenshotGroup.className = 'sample-row';
    screenshotGroup.innerHTML = '<span class="sample-label">📸 Test OCR Screenshots</span>';

    SAMPLE_MESSAGES.forEach(sample => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'chip-btn';
      btn.textContent = sample.title;
      btn.dataset.id = sample.id;
      btn.addEventListener('click', () => loadSample(sample.id));

      if (sample.group === 'scams') {
        scamGroup.appendChild(btn);
      } else {
        genuineGroup.appendChild(btn);
      }
    });

    const testScreens = [
      {
        title: '📱 Bank Phishing Screenshot',
        sender: 'AX-SBIINB',
        text: 'SBI ALERT: Your KYC is incomplete and your account will be blocked today. Update immediately at http://sbi-kyc-update.com/login and share the OTP to confirm.',
        scam: true
      },
      {
        title: '📦 Courier Scam Screenshot',
        sender: 'DTDC-ALERT',
        text: 'DTDC: Your package is held at customs. Pay clearance fee of Rs 85 at http://dtdc-clearance.example/pay within 24 hours or it will be returned.',
        scam: true
      },
      {
        title: '🛍️ Safe Flipkart Screenshot',
        sender: 'FLPKRT',
        text: 'Your Flipkart order for boAt Earbuds is shipped and will arrive by Thursday. Track here: https://www.flipkart.com/orders',
        scam: false
      }
    ];

    testScreens.forEach(ts => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'chip-btn';
      btn.textContent = ts.title;
      btn.addEventListener('click', async () => {
        const file = await createSampleScreenshot(ts.title, ts.sender, ts.text, ts.scam);
        handleImageFile(file);
      });
      screenshotGroup.appendChild(btn);
    });

    sampleChipsContainer.appendChild(scamGroup);
    sampleChipsContainer.appendChild(genuineGroup);
    sampleChipsContainer.appendChild(screenshotGroup);
  }

  function loadSample(id) {
    const sample = SAMPLE_MESSAGES.find(s => s.id === id);
    if (!sample) return;

    messageInput.value = sample.text;
    activeSampleId = id;
    sampleNote.textContent = `Scenario: ${sample.title} (${sample.badge}). ${sample.notes}`;

    document.querySelectorAll('.chip-btn').forEach(c => {
      c.classList.toggle('active', c.dataset.id === id);
    });

    runAnalysis(true);
  }

  function handleClear() {
    messageInput.value = '';
    activeSampleId = null;
    sampleNote.textContent = '';
    hideAlert();
    currentAnalysis = null;
    resultsContainer.innerHTML = '';
    emptyState.hidden = false;
    document.querySelectorAll('.chip-btn').forEach(c => c.classList.remove('active'));
    messageInput.focus();
  }

  // Analysis Runner
  function runAnalysis(validate) {
    const text = messageInput.value;
    if (validate) {
      const trimmed = text.trim();
      if (!trimmed) {
        showAlert('Please paste a message or website link first (SMS, email, WhatsApp message, or URL).');
        emptyState.hidden = false;
        resultsContainer.innerHTML = '';
        currentAnalysis = null;
        return;
      }
      const isUrlCandidate = /^(?:https?:\/\/|www\.)?[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(trimmed);
      if (!isUrlCandidate && trimmed.length < 15) {
        showAlert('That message is too short to evaluate. Please paste the full message, sender, or website link.');
        emptyState.hidden = false;
        resultsContainer.innerHTML = '';
        currentAnalysis = null;
        return;
      }
      if (!isUrlCandidate && !/[A-Za-z\u0900-\u097F]{3,}/.test(trimmed)) {
        showAlert('The text does not look like a recognizable message or website link. Please paste the actual text you received.');
        emptyState.hidden = false;
        resultsContainer.innerHTML = '';
        currentAnalysis = null;
        return;
      }
    }

    hideAlert();
    emptyState.hidden = true;
    const analysis = analyzeMessage(text, customWeights);
    currentAnalysis = analysis;
    renderResults(analysis);
  }

  function showAlert(msg) {
    alertBox.textContent = msg;
    alertBox.hidden = false;
  }

  function hideAlert() {
    alertBox.hidden = true;
    alertBox.textContent = '';
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Results Renderer
  function renderResults(a) {
    resultsContainer.innerHTML = '';
    const tr = (typeof UI_TRANSLATIONS !== 'undefined' && UI_TRANSLATIONS[currentLang]) 
      ? UI_TRANSLATIONS[currentLang] 
      : UI_TRANSLATIONS['en'];

    // 1. Verdict Banner with Gauge
    const banner = document.createElement('div');
    banner.className = `verdict-banner ${a.riskLevel}`;

    let headline = '';
    let explanation = '';
    let badgeText = '';
    if (a.riskLevel === 'high') {
      headline = tr.highTitle;
      explanation = tr.highDesc;
      badgeText = currentLang === 'hi' ? '🚨 फर्जी / धोखाधड़ी (FAKE)' : (currentLang === 'hinglish' ? '🚨 FAKE / SCAM' : '🚨 FAKE / SCAM');
    } else if (a.riskLevel === 'medium') {
      headline = tr.medTitle;
      explanation = tr.medDesc;
      badgeText = currentLang === 'hi' ? '⚠️ संदिग्ध (SUSPICIOUS)' : (currentLang === 'hinglish' ? '⚠️ SUSPICIOUS' : '⚠️ SUSPICIOUS');
    } else {
      if (a.findings.length === 0) {
        headline = tr.lowZeroTitle;
        explanation = tr.lowZeroDesc;
        badgeText = currentLang === 'hi' ? '✅ सुरक्षित / सही (SAFE)' : (currentLang === 'hinglish' ? '✅ RIGHT / SAFE' : '✅ RIGHT / SAFE');
      } else {
        headline = tr.lowMildTitle;
        explanation = tr.lowMildDesc;
        badgeText = currentLang === 'hi' ? '✅ सुरक्षित / सही (SAFE)' : (currentLang === 'hinglish' ? '✅ RIGHT / SAFE' : '✅ RIGHT / SAFE');
      }
    }

    const scoreCol = document.createElement('div');
    scoreCol.className = 'score-badge';
    scoreCol.innerHTML = `
      <div class="score-number">${a.finalScore}</div>
      <div class="score-total">/ 100 Risk Points</div>
      <div class="risk-level-tag">${badgeText}</div>
    `;

    const contentCol = document.createElement('div');
    contentCol.className = 'verdict-content';

    // Formula line
    let formulaText = '';
    if (!a.findings.length) {
      formulaText = 'No scam rules triggered (0 / 100)';
    } else {
      formulaText = a.findings.map(f => `+${f.pts}`).join(' ') + ` = ${a.rawScore}`;
      if (a.rawScore > 100) formulaText += ' (capped at 100 max)';
      if (a.isCapped) formulaText += ' (capped at 59: soft signs alone cannot reach High Risk)';
      formulaText += ' / 100';
    }

    contentCol.innerHTML = `
      <h3>${headline}</h3>
      <p class="summary-text">${explanation}</p>
      <div class="meter-container">
        <div class="gauge-track">
          <div class="gauge-zone low" title="Low Risk: 0-29"></div>
          <div class="gauge-zone medium" title="Medium Risk: 30-59"></div>
          <div class="gauge-zone high" title="High Risk: 60-100"></div>
          <div class="gauge-needle" style="left: ${Math.max(2, Math.min(98, a.finalScore))}%"></div>
        </div>
        <div class="gauge-labels">
          <span>0 (Safe)</span>
          <span>30 (Medium)</span>
          <span>60 (High Risk)</span>
          <span>100</span>
        </div>
      </div>
      <div class="score-formula-line">${formulaText}</div>
    `;

    banner.appendChild(scoreCol);
    banner.appendChild(contentCol);
    resultsContainer.appendChild(banner);

    // 2. Two-Column Grid: (Left: Marked message, Email breakdown, Findings) (Right: Next Steps, Panic, Share, Report)
    const grid = document.createElement('div');
    grid.className = 'results-grid';

    const leftCol = document.createElement('div');
    leftCol.className = 'card';

    // Anti-Evasion Alert Banner if obfuscations were normalized
    if (a.evasionFlags && a.evasionFlags.length > 0) {
      const evasionBox = document.createElement('div');
      evasionBox.className = 'alert-message';
      evasionBox.style.cssText = 'background-color: var(--risk-med-bg); border: 1.5px solid var(--risk-med-border); color: var(--risk-med); font-size: 13.5px; margin-bottom: 12px;';
      evasionBox.innerHTML = `<strong>⚠️ Anti-Evasion Guard Alert:</strong> ${a.evasionFlags.join(' ')}`;
      leftCol.appendChild(evasionBox);
    }

    if (a.emailHeader) {
      const emailCard = document.createElement('div');
      emailCard.className = `email-header-card ${a.emailHeader.isSpoofed ? 'spoofed' : a.emailHeader.isVerified ? 'verified' : ''}`;
      emailCard.innerHTML = `
        <div class="email-header-title">
          <span style="display: flex; align-items: center; gap: 6px;">
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
            Email Sender Identity Breakdown
          </span>
          <span class="type-pill ${a.emailHeader.isSpoofed ? 'hard' : 'soft'}">
            ${a.emailHeader.isSpoofed ? '🚨 Impersonation Detected' : a.emailHeader.isVerified ? '✓ Verified Domain' : 'External Email'}
          </span>
        </div>
        <div class="email-comparison-grid">
          <div class="email-claim-box">
            <span class="email-claim-label">Claimed Sender Identity</span>
            <span class="email-claim-val">${escapeHtml(a.emailHeader.displayName)}</span>
          </div>
          <div class="email-claim-box">
            <span class="email-claim-label">Actual Originating Address</span>
            <span class="email-claim-val" style="color: ${a.emailHeader.isSpoofed ? 'var(--risk-high)' : 'var(--text-main)'}; font-weight: 700;">${escapeHtml(a.emailHeader.actualEmail)}</span>
          </div>
        </div>
        ${a.emailHeader.isSpoofed ? `
          <p style="font-size: 13px; color: var(--risk-high); margin: 0; line-height: 1.4;">
            ⚠️ <strong>Sender Spoofing Alert:</strong> The sender name says "${escapeHtml(a.emailHeader.claimedBrand)}", but the email address is <code>@${escapeHtml(a.emailHeader.domain)}</code>. Legitimate companies never send security notices or account warnings from free webmail or unverified third-party domains.
          </p>
        ` : ''}
      `;
      leftCol.appendChild(emailCard);
    }

    // Website & Link Safety Inspector (Fake or Right?)
    if (a.links && a.links.length > 0) {
      a.links.forEach(l => {
        const linkCard = document.createElement('div');
        linkCard.className = `link-inspector-card ${l.status}`;

        let statusBadgeText = '';
        if (l.status === 'fake') {
          statusBadgeText = currentLang === 'hi' ? '🚨 फर्जी वेबसाइट (FAKE)' : '🚨 FAKE / IMPOSTOR WEBSITE';
        } else if (l.status === 'official') {
          statusBadgeText = currentLang === 'hi' ? '✅ आधिकारिक वेबसाइट (RIGHT)' : '✅ VERIFIED OFFICIAL (RIGHT)';
        } else if (l.status === 'suspicious') {
          statusBadgeText = l.isShortener 
            ? (currentLang === 'hi' ? '⚠️ छिपा हुआ लिंक (DANGER)' : '⚠️ HIDDEN SHORTENED LINK')
            : (currentLang === 'hi' ? '⚠️ संदिग्ध डोमेन' : '⚠️ HIGH-RISK DOMAIN');
        } else {
          statusBadgeText = currentLang === 'hi' ? '⚠️ असत्यापित लिंक' : '⚠️ UNVERIFIED WEBSITE';
        }

        linkCard.innerHTML = `
          <div class="link-inspector-header">
            <div class="link-inspector-title">
              <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
              </svg>
              <span>Link Safety Inspector (Fake or Right?)</span>
            </div>
            <span class="link-status-badge ${l.badgeClass}">${statusBadgeText}</span>
          </div>
          <div class="link-details-body">
            <div class="link-url-row">
              <span style="font-weight: 600; color: var(--text-muted);">Link Tested:</span>
              <code class="link-url-code">${escapeHtml(l.url)}</code>
            </div>
            ${l.impersonatedBrand ? `
              <div class="link-advice-box" style="background-color: var(--risk-high-bg); border-color: var(--risk-high-border); color: var(--risk-high);">
                <strong>🚨 Phishing Impostor Alert:</strong> This website is pretending to belong to <strong>${escapeHtml(l.impersonatedBrand.name)}</strong>, but the domain <code>${escapeHtml(l.host)}</code> is an unofficial copycat. The real official website is <strong>${escapeHtml(l.officialDomains.join(' or '))}</strong>.
              </div>
            ` : ''}
            ${l.isOfficial ? `
              <div class="link-advice-box" style="background-color: var(--risk-low-bg); border-color: var(--risk-low-border); color: var(--risk-low);">
                <strong>✅ Genuine Official Website:</strong> This link points directly to the certified official domain of <strong>${escapeHtml(l.officialBrand ? l.officialBrand.name : l.host)}</strong>. It is authentic and safe to visit.
              </div>
            ` : ''}
            ${l.isShortener ? `
              <div class="link-advice-box" style="background-color: var(--risk-med-bg); border-color: var(--risk-med-border); color: var(--risk-med);">
                <strong>⚠️ Hidden Destination Warning:</strong> This link is masked using the shortener <code>${escapeHtml(l.host)}</code> to hide where it really leads. Scammers use this so you cannot see the real website.
              </div>
            ` : ''}
            <div class="link-advice-box">
              <span class="people-verdict-tag">👉 What You Should Do:</span>
              <span>${escapeHtml(l.peoplesAdvice)}</span>
            </div>
          </div>
        `;
        leftCol.appendChild(linkCard);
      });
    }

    // Marked message display
    const markedTitle = document.createElement('h3');
    markedTitle.textContent = 'Highlighted Message & Red Flags';
    leftCol.appendChild(markedTitle);

    const markedBox = document.createElement('div');
    markedBox.className = 'marked-container';
    renderHighlightedText(markedBox, a);
    leftCol.appendChild(markedBox);

    if (a.findings.length > 0) {
      const legend = document.createElement('div');
      legend.className = 'highlight-legend';
      legend.innerHTML = `
        <span class="legend-item"><span class="legend-box hard"></span> Hard Threat (Direct danger)</span>
        <span class="legend-item"><span class="legend-box soft"></span> Soft Tactic (Pressure / Urgency)</span>
        <span style="margin-left: auto;">Tip: Click any finding to jump to its text</span>
      `;
      leftCol.appendChild(legend);
    }

    // Findings List / Table
    const findingsHeader = document.createElement('h3');
    findingsHeader.style.marginTop = '16px';
    findingsHeader.textContent = a.findings.length ? `Detected Warning Signs (${a.findings.length})` : 'Findings';
    leftCol.appendChild(findingsHeader);

    const findingsContainer = document.createElement('div');
    findingsContainer.className = 'findings-table-container';

    if (!a.findings.length) {
      findingsContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 14px;">No suspicious warning signs found.</p>';
    } else {
      a.findings.forEach(f => {
        const row = document.createElement('div');
        row.className = 'finding-row';
        row.dataset.badge = f.badgeNumber;
        row.innerHTML = `
          <div class="badge-circle">${f.badgeNumber}</div>
          <div class="finding-details">
            <div class="finding-title-row">
              <span class="finding-name">${f.name}</span>
              <span class="type-pill ${f.hard ? 'hard' : 'soft'}">${f.hard ? 'Hard Sign' : 'Soft Sign'}</span>
            </div>
            <div class="finding-quote">"${f.foundQuotes.join('", "')}"</div>
            ${f.detail ? `<div style="font-size: 12.5px; color: var(--risk-high);">${f.detail}</div>` : ''}
            <div class="finding-why">${f.why}</div>
          </div>
          <div class="finding-pts">+${f.pts}</div>
        `;

        // Interactive click jumps to highlighted text
        row.addEventListener('click', () => {
          document.querySelectorAll('.finding-row').forEach(r => r.classList.remove('active'));
          row.classList.add('active');

          const targetMark = markedBox.querySelector(`mark[data-badge="${f.badgeNumber}"]`);
          if (targetMark) {
            document.querySelectorAll('mark.scam-mark').forEach(el => el.classList.remove('active-focus'));
            targetMark.classList.add('active-focus');
            targetMark.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
        });

        findingsContainer.appendChild(row);
      });
    }
    leftCol.appendChild(findingsContainer);

    // Safe Signals if any
    if (a.safeSignals.length > 0) {
      const safeBox = document.createElement('div');
      safeBox.className = 'safe-signals-box';
      safeBox.innerHTML = '<h4><svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> Legitimate Trust Signals Detected</h4>';

      a.safeSignals.forEach(sig => {
        const item = document.createElement('div');
        item.className = 'safe-signal-item';
        item.innerHTML = `<span>✓</span><span>${SAFE_SIGNALS[sig.id](sig.extra)}</span>`;
        safeBox.appendChild(item);
      });
      leftCol.appendChild(safeBox);
    }

    grid.appendChild(leftCol);

    // Right Column: Next Steps, Panic Playbook, WhatsApp Family Alert, Formal Police Report
    const rightCol = document.createElement('div');
    rightCol.style.display = 'flex';
    rightCol.style.flexDirection = 'column';
    rightCol.style.gap = '20px';

    // 1. Safe Next Steps
    const stepsCard = document.createElement('div');
    stepsCard.className = 'card';
    stepsCard.innerHTML = `<h3>${tr.safeNextSteps}</h3>`;

    const stepsList = document.createElement('div');
    stepsList.className = 'steps-list';

    const safeSteps = generateSafeSteps(a, currentLang);
    safeSteps.forEach(step => {
      const stepItem = document.createElement('div');
      stepItem.className = 'step-card';
      stepItem.innerHTML = `<span>${step}</span>`;
      stepsList.appendChild(stepItem);
    });
    stepsCard.appendChild(stepsList);

    // Helpline Callout
    const helplineBox = document.createElement('div');
    helplineBox.className = 'helpline-box';
    helplineBox.innerHTML = `
      <p>Official Indian Cyber Fraud Reporting:</p>
      <div>Helpline: <strong>Dial 1930</strong> | Portal: <strong>cybercrime.gov.in</strong></div>
      <p style="font-size: 12px; margin-top: 4px; opacity: 0.85;">Reporting immediately within the first 2-3 hours gives the highest chance of freezing fraudulent bank transfers.</p>
    `;
    stepsCard.appendChild(helplineBox);
    rightCol.appendChild(stepsCard);

    // 2. Emergency Panic Help Accordion
    const panicDetails = document.createElement('details');
    panicDetails.className = 'panic-accordion';
    panicDetails.innerHTML = `
      <summary>I already clicked, shared OTP, or sent money — What should I do now?</summary>
      <div class="panic-content">
        <div class="panic-section">
          <h5>1. If you shared an OTP, UPI PIN, or Netbanking password:</h5>
          <ul>
            <li>Immediately call your bank's toll-free number printed on the back of your debit card.</li>
            <li>Request an immediate freeze on your net banking access and card transactions.</li>
            <li>Change your netbanking password and UPI PIN from a safe device.</li>
          </ul>
        </div>
        <div class="panic-section">
          <h5>2. If you transferred money to the scammer:</h5>
          <ul>
            <li>Dial <strong>1930</strong> immediately to lodge a complaint with the National Cyber Crime Reporting Portal.</li>
            <li>Note down transaction ID, recipient UPI ID/account number, and exact timestamp.</li>
            <li>Visit your local cyber police station or file an official FIR at <strong>cybercrime.gov.in</strong>.</li>
          </ul>
        </div>
        <div class="panic-section">
          <h5>3. If you downloaded an APK or remote tool (AnyDesk/TeamViewer):</h5>
          <ul>
            <li>Turn on <strong>Airplane Mode</strong> immediately to cut off internet access.</li>
            <li>Uninstall the downloaded application and clear browser download cache.</li>
            <li>Check for unknown device administrators in your Android Settings.</li>
          </ul>
        </div>
      </div>
    `;
    rightCol.appendChild(panicDetails);

    // 3. Family Alert Generator
    const shareCard = document.createElement('div');
    shareCard.className = 'card share-box';
    const alertMsgText = generateFamilyAlertText(a);

    shareCard.innerHTML = `
      <h3>Warn Your Family on WhatsApp</h3>
      <p style="font-size: 13.5px; color: var(--text-muted);">Share this pre-written message with parents, friends, or family groups to keep them protected without forwarding any harmful links.</p>
      <textarea class="share-preview" readonly>${alertMsgText}</textarea>
      <div style="display: flex; gap: 10px; align-items: center;">
        <button class="btn primary" id="copyAlertBtn" type="button">
          <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
          Copy Warning Text
        </button>
        <span id="copySuccessMsg" style="font-size: 13px; color: var(--risk-low); font-weight: 600;" hidden>Copied!</span>
      </div>
    `;

    const copyBtn = shareCard.querySelector('#copyAlertBtn');
    const copySuccess = shareCard.querySelector('#copySuccessMsg');
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(alertMsgText).then(() => {
        copySuccess.hidden = false;
        setTimeout(() => { copySuccess.hidden = true; }, 3000);
      });
    });

    rightCol.appendChild(shareCard);

    // 4. Formal Cybercrime Incident Report Card
    const reportCard = document.createElement('div');
    reportCard.className = 'card incident-report-card';
    const reportText = generatePoliceReportText(a);

    reportCard.innerHTML = `
      <h3>Formal Incident Report</h3>
      <p style="font-size: 13px; color: var(--text-muted);">Formatted summary ready to attach to an official cybercrime.gov.in complaint or bank dispute form.</p>
      <textarea class="incident-report-textarea" readonly>${reportText}</textarea>
      <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
        <button class="btn" id="copyReportBtn" type="button">
          <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2"/></svg>
          Copy Incident Report
        </button>
        <button class="btn" id="downloadReportBtn" type="button">
          <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
          Download .TXT
        </button>
        <span id="copyReportSuccess" style="font-size: 13px; color: var(--risk-low); font-weight: 600;" hidden>Copied!</span>
      </div>
    `;

    const copyReportBtn = reportCard.querySelector('#copyReportBtn');
    const downloadReportBtn = reportCard.querySelector('#downloadReportBtn');
    const copyReportSuccess = reportCard.querySelector('#copyReportSuccess');

    copyReportBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(reportText).then(() => {
        copyReportSuccess.hidden = false;
        setTimeout(() => { copyReportSuccess.hidden = true; }, 3000);
      });
    });

    downloadReportBtn.addEventListener('click', () => {
      const blob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const aEl = document.createElement('a');
      aEl.href = url;
      aEl.download = `ScamSpotter-Incident-Report-${Date.now()}.txt`;
      aEl.click();
      URL.revokeObjectURL(url);
    });

    rightCol.appendChild(reportCard);
    grid.appendChild(rightCol);

    resultsContainer.appendChild(grid);
  }

  // Render Highlighted Text
  function renderHighlightedText(container, a) {
    container.innerHTML = '';
    const text = a.originalText;
    let cursor = 0;

    a.cleanMarks.forEach(m => {
      if (m.start > cursor) {
        container.appendChild(document.createTextNode(text.slice(cursor, m.start)));
      }

      const markEl = document.createElement('mark');
      markEl.className = `scam-mark ${m.hard ? 'hard' : 'soft'}`;
      markEl.dataset.badge = m.badgeNumber;
      markEl.textContent = text.slice(m.start, m.end);

      const badge = document.createElement('span');
      badge.className = 'badge-num';
      badge.textContent = m.badgeNumber;
      markEl.appendChild(badge);

      markEl.addEventListener('click', () => {
        document.querySelectorAll('mark.scam-mark').forEach(el => el.classList.remove('active-focus'));
        markEl.classList.add('active-focus');

        const correspondingRow = document.querySelector(`.finding-row[data-badge="${m.badgeNumber}"]`);
        if (correspondingRow) {
          document.querySelectorAll('.finding-row').forEach(r => r.classList.remove('active'));
          correspondingRow.classList.add('active');
          correspondingRow.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      });

      container.appendChild(markEl);
      cursor = m.end;
    });

    if (cursor < text.length) {
      container.appendChild(document.createTextNode(text.slice(cursor)));
    }
  }

  // Safe Next Steps Logic
  function generateSafeSteps(a, lang = 'en') {
    const tr = (typeof UI_TRANSLATIONS !== 'undefined' && UI_TRANSLATIONS[lang]) 
      ? UI_TRANSLATIONS[lang] 
      : UI_TRANSLATIONS['en'];

    const steps = [];
    if (a.riskLevel === 'low' && !a.findings.length) {
      steps.push(tr.officialChannels || 'Contact the institution solely through official channels.');
      steps.push(tr.neverShareOtp || 'Never share or type your OTP with anyone.');
      return steps;
    }

    steps.push(tr.doNotClick || 'Do NOT click on any link or open attached files in this message.');
    steps.push(tr.doNotCall || 'Do NOT call back any mobile number or WhatsApp contact mentioned inside the message.');

    if (a.findings.some(f => f.id === 'creds')) {
      steps.push(tr.neverShareOtp || 'Never share or type your OTP, card CVV, or UPI PIN under any circumstances.');
    }
    if (a.findings.some(f => f.id === 'money')) {
      steps.push(tr.noUpiCollect || 'Do not approve any UPI collect requests or pay "clearance / registration" deposits.');
    }
    if (a.findings.some(f => f.id === 'authority')) {
      steps.push(tr.authorityHangUp || 'Hang up immediately. No police or court conducts interrogations or "digital arrests" via video calls.');
    }
    if (a.findings.some(f => f.id === 'install')) {
      steps.push(tr.noApk || 'Do not install remote assistance apps (AnyDesk/TeamViewer) or APK files.');
    }

    steps.push(tr.officialChannels || 'Contact the institution solely through its official mobile banking app, official website, or the phone number printed directly on your ATM passbook/card.');
    return steps;
  }

  // Family WhatsApp Alert Message Generator
  function generateFamilyAlertText(a) {
    const flags = a.findings.map(f => f.name).join(', ');
    const risk = a.riskLevel.toUpperCase();
    return `🚨 Scam Alert for Family & Friends\n\nI verified a suspicious message using Scam Spotter and it was flagged as ${risk} RISK.\n${flags ? `Warning Signs Detected: ${flags}\n` : ''}\nImportant reminders to keep everyone safe:\n• Never click unknown links in SMS or WhatsApp.\n• Banks NEVER ask for OTP, PIN, or CVV.\n• Police/CBI never arrest people over video calls.\n• Report any fraud immediately at cybercrime.gov.in or call helpline 1930.`;
  }

  // Formal Incident Summary for cybercrime.gov.in or Bank Branches
  function generatePoliceReportText(a) {
    const dateStr = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
    const redFlags = a.findings.map(f => `- ${f.name} (+${f.pts} pts): "${f.foundQuotes.join(', ')}"\n  Reason: ${f.why}`).join('\n');
    
    return `FORMAL CYBER INCIDENT SUMMARY FOR COMPLAINT / POLICE REPORT
Generated via Scam Spotter (Transparent Anti-Fraud Engine)
Date & Timestamp: ${dateStr} IST
Assessment: ${a.riskLevel.toUpperCase()} RISK (${a.finalScore} / 100)

1. INCIDENT DESCRIPTION:
Suspicious communication received claiming to be from an official entity.

2. SUSPICIOUS MESSAGE EXCERPT:
"""
${a.originalText}
"""

3. DETECTED FRAUDULENT INDICATORS:
${redFlags || 'No overt red flags detected.'}

4. SUGGESTED LEGAL CATEGORIES UNDER INDIAN LAW:
- Section 66D of Information Technology Act, 2000 (Cheating by personation using computer resource)
- Section 419 / 420 of Indian Penal Code (Cheating and dishonestly inducing delivery of property)
- Section 318 / 319 of Bharatiya Nyaya Sanhita (BNS), 2023

5. COMPLAINANT ACTION LOG:
- Evidence preserved and verified locally.
- Verified through Scam Spotter client-side rule assessment.
- Escalated to National Cyber Crime Reporting Portal (cybercrime.gov.in) / Helpline 1930.`;
  }

  // Rulebook Tuner
  function buildRulebookTable() {
    rulesTableBody.innerHTML = '';

    RULE_ORDER.forEach(id => {
      const meta = RULE_METADATA[id];
      const tr = document.createElement('tr');

      tr.innerHTML = `
        <td style="font-weight: 700;">${meta.name}</td>
        <td style="color: var(--text-muted); font-size: 13.5px;">${meta.rule}</td>
        <td><span class="type-pill ${meta.hard ? 'hard' : 'soft'}">${meta.hard ? 'Hard Sign' : 'Soft Sign'}</span></td>
        <td>
          <input type="number" min="0" max="100" class="rule-input-pts" id="input-weight-${id}" value="${customWeights[id]}" />
        </td>
      `;

      const input = tr.querySelector(`#input-weight-${id}`);
      input.addEventListener('input', () => {
        const val = parseInt(input.value, 10);
        customWeights[id] = isNaN(val) ? DEFAULT_POINTS[id] : Math.max(0, Math.min(100, val));
        saveWeights(customWeights);
        checkWeightsModified();
        if (currentAnalysis) runAnalysis(false);
        runSelfTestCorpus();
      });

      rulesTableBody.appendChild(tr);
    });

    checkWeightsModified();
  }

  function handleResetWeights() {
    customWeights = Object.assign({}, DEFAULT_POINTS);
    saveWeights(customWeights);
    RULE_ORDER.forEach(id => {
      const inp = document.getElementById(`input-weight-${id}`);
      if (inp) inp.value = DEFAULT_POINTS[id];
    });
    checkWeightsModified();
    if (currentAnalysis) runAnalysis(false);
    runSelfTestCorpus();
  }

  function checkWeightsModified() {
    const isCustom = RULE_ORDER.some(id => customWeights[id] !== DEFAULT_POINTS[id]);
    weightsStatus.textContent = isCustom ? 'Custom rule weights are currently active.' : 'Default standard weights active.';
    weightsStatus.style.color = isCustom ? 'var(--primary)' : 'var(--text-muted)';
  }

  function loadWeights() {
    try {
      const saved = localStorage.getItem('scam-spotter-weights');
      return saved ? JSON.parse(saved) : Object.assign({}, DEFAULT_POINTS);
    } catch (e) {
      return Object.assign({}, DEFAULT_POINTS);
    }
  }

  function saveWeights(w) {
    try {
      localStorage.setItem('scam-spotter-weights', JSON.stringify(w));
    } catch (e) {}
  }

  // Self-Test Suite Runner
  function runSelfTestCorpus() {
    testListContainer.innerHTML = '';
    const stats = { total: TEST_CORPUS.length, correct: 0, high: [0, 0], low: [0, 0], med: [0, 0] };

    TEST_CORPUS.forEach(item => {
      const res = analyzeMessage(item.text, customWeights);
      let passed = false;

      if (item.expect === 'high') {
        stats.high[1]++;
        passed = res.riskLevel === 'high';
        if (passed) stats.high[0]++;
      } else if (item.expect === 'low') {
        stats.low[1]++;
        passed = res.riskLevel === 'low';
        if (passed) stats.low[0]++;
      } else {
        stats.med[1]++;
        passed = res.riskLevel === 'medium' || res.riskLevel === 'high';
        if (passed) stats.med[0]++;
      }

      if (passed) stats.correct++;

      const row = document.createElement('div');
      row.style.cssText = 'display: grid; grid-template-columns: 80px 1fr auto auto; gap: 12px; padding: 10px 14px; border-bottom: 1px solid var(--border); align-items: center; font-size: 13.5px;';

      row.innerHTML = `
        <span class="risk-level-tag" style="background-color: var(--risk-${res.riskLevel === 'high' ? 'high' : res.riskLevel === 'medium' ? 'med' : 'low'}); color: #FFF; text-align: center;">${res.riskLevel.toUpperCase()}</span>
        <div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${item.text}">
          ${item.text}
          <div style="font-family: var(--font-body); font-size: 11.5px; color: var(--text-muted);">${item.group} — Expected: ${item.expect.toUpperCase()}</div>
        </div>
        <div style="font-family: var(--font-mono); font-weight: 700;">${res.finalScore}/100</div>
        <button class="btn" style="padding: 4px 10px; font-size: 12px;" type="button">Test in Checker</button>
      `;

      row.querySelector('button').addEventListener('click', () => {
        messageInput.value = item.text;
        document.querySelector('[data-tab="tab-checker"]').click();
        runAnalysis(true);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });

      testListContainer.appendChild(row);
    });

    testStatsContainer.innerHTML = `
      <div class="stat-box">
        <span class="stat-val">${stats.correct} / ${stats.total}</span>
        <span class="stat-label">Overall Accuracy</span>
      </div>
      <div class="stat-box">
        <span class="stat-val">${stats.high[0]} / ${stats.high[1]}</span>
        <span class="stat-label">Scams Detected (High)</span>
      </div>
      <div class="stat-box">
        <span class="stat-val">${stats.low[0]} / ${stats.low[1]}</span>
        <span class="stat-label">Normal Messages (Low)</span>
      </div>
      <div class="stat-box">
        <span class="stat-val">${stats.med[0]} / ${stats.med[1]}</span>
        <span class="stat-label">Borderline Warnings</span>
      </div>
    `;
  }

  // Quiz Game Logic
  let quizState = {
    questions: [],
    currentIndex: 0,
    score: 0,
    isAnswered: false
  };

  function initQuiz() {
    quizState.questions = [...SAMPLE_MESSAGES].sort(() => Math.random() - 0.5);
    quizState.currentIndex = 0;
    quizState.score = 0;
    quizState.isAnswered = false;
    renderQuizQuestion();
  }

  function renderQuizQuestion() {
    quizBox.innerHTML = '';

    if (quizState.currentIndex >= quizState.questions.length) {
      quizBox.innerHTML = `
        <div style="text-align: center; padding: 30px 20px; display: flex; flex-direction: column; gap: 14px; align-items: center;">
          <h3 style="font-size: 26px;">Quiz Complete! 🎉</h3>
          <p style="font-size: 18px; color: var(--text-muted);">You scored <strong>${quizState.score}</strong> out of <strong>${quizState.questions.length}</strong>.</p>
          <p style="font-size: 14px; max-width: 500px; color: var(--text-muted);">
            ${quizState.score === quizState.questions.length 
              ? 'Flawless! You have sharp eyes and won\'t be easily fooled by scammers.' 
              : 'Great practice! Remember to always look out for artificial deadlines, unverified domains, and requests for codes.'}
          </p>
          <button class="btn primary" id="restartQuizBtn" type="button">Play Again</button>
        </div>
      `;
      quizBox.querySelector('#restartQuizBtn').addEventListener('click', initQuiz);
      return;
    }

    const q = quizState.questions[quizState.currentIndex];

    quizBox.innerHTML = `
      <div class="quiz-header">
        <span>Question <strong>${quizState.currentIndex + 1}</strong> of <strong>${quizState.questions.length}</strong></span>
        <span>Score: <strong>${quizState.score}</strong></span>
      </div>
      <h4 style="font-size: 17px; font-weight: 700;">Is this message a scam or genuine?</h4>
      <div class="quiz-msg-box">${q.text}</div>
      <div class="quiz-buttons">
        <button class="btn primary" id="btnAnswerScam" type="button" style="background-color: var(--risk-high); border-color: var(--risk-high);">⚠️ Flag as Scam</button>
        <button class="btn" id="btnAnswerSafe" type="button">✓ Looks Safe</button>
      </div>
      <div id="quizFeedbackBox" class="quiz-feedback" hidden></div>
    `;

    const btnScam = quizBox.querySelector('#btnAnswerScam');
    const btnSafe = quizBox.querySelector('#btnAnswerSafe');
    const feedbackBox = quizBox.querySelector('#quizFeedbackBox');

    function handleAnswer(userChoice) {
      if (quizState.isAnswered) return;
      quizState.isAnswered = true;

      const isActualScam = q.group === 'scams';
      const userSaysScam = userChoice === 'scam';
      const isCorrect = userSaysScam === isActualScam;

      if (isCorrect) quizState.score++;

      btnScam.disabled = true;
      btnSafe.disabled = true;

      const analysis = analyzeMessage(q.text, customWeights);
      feedbackBox.className = `quiz-feedback ${isCorrect ? 'correct' : 'wrong'}`;
      feedbackBox.hidden = false;

      feedbackBox.innerHTML = `
        <div style="font-family: var(--font-display); font-size: 16px; font-weight: 800; color: ${isCorrect ? 'var(--risk-low)' : 'var(--risk-high)'};">
          ${isCorrect ? '✓ Correct Decision!' : '✗ Not Quite!'}
        </div>
        <p style="font-size: 14px;">This message was scored <strong>${analysis.finalScore}/100 (${analysis.riskLevel.toUpperCase()} RISK)</strong> by the rules.</p>
        <p style="font-size: 13.5px; color: var(--text-muted);">${q.notes}</p>
        <button class="btn primary" id="btnNextQuiz" type="button" style="width: fit-content; margin-top: 8px;">
          ${quizState.currentIndex + 1 >= quizState.questions.length ? 'View Final Score' : 'Next Message →'}
        </button>
      `;

      feedbackBox.querySelector('#btnNextQuiz').addEventListener('click', () => {
        quizState.currentIndex++;
        quizState.isAnswered = false;
        renderQuizQuestion();
      });
    }

    btnScam.addEventListener('click', () => handleAnswer('scam'));
    btnSafe.addEventListener('click', () => handleAnswer('safe'));
  }

  // Interactive ROI Calculator Logic (Campus & Enterprise Protection)
  function initRoiCalculator() {
    function updateRoi() {
      if (!roiOrgType || !roiScaleInput) return;
      const isCollege = roiOrgType.value === 'college';
      const val = parseInt(roiScaleInput.value, 10);

      if (isCollege) {
        roiScaleLabel.innerHTML = `Students Enrolled: <strong style="color: var(--primary);">${val.toLocaleString('en-IN')}</strong>`;
        const cost = val * 15;
        // 2.8% of students hit, avg scam loss ₹25,000, 70% intercepted
        const prevented = Math.round(val * 0.028 * 25000 * 0.70);
        const multiplier = (prevented / Math.max(1, cost)).toFixed(1);

        if (roiCostOut) roiCostOut.textContent = `₹${cost.toLocaleString('en-IN')}`;
        if (roiSavingsOut) roiSavingsOut.textContent = `₹${prevented.toLocaleString('en-IN')}`;
        if (roiMultiplierOut) roiMultiplierOut.textContent = `${multiplier}x`;
      } else {
        const checks = val * 10;
        roiScaleLabel.innerHTML = `Monthly Verification Checks: <strong style="color: var(--primary);">${checks.toLocaleString('en-IN')}</strong>`;
        const cost = Math.round(checks * 0.20 * 12);
        // 0.8% fraudulent attempts intercepted, avg saved chargeback/complaint ₹8,000
        const prevented = Math.round(checks * 12 * 0.008 * 8000);
        const multiplier = (prevented / Math.max(1, cost)).toFixed(1);

        if (roiCostOut) roiCostOut.textContent = `₹${cost.toLocaleString('en-IN')}/yr`;
        if (roiSavingsOut) roiSavingsOut.textContent = `₹${prevented.toLocaleString('en-IN')}`;
        if (roiMultiplierOut) roiMultiplierOut.textContent = `${multiplier}x`;
      }
    }

    if (roiOrgType && roiScaleInput) {
      roiOrgType.addEventListener('change', updateRoi);
      roiScaleInput.addEventListener('input', updateRoi);
      updateRoi();
    }
  }
});

