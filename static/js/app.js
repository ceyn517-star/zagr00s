/**
 * ZAGROS - Integrated ID Search with Email & OSINT
 * Simplified JavaScript for unified search experience
 */

const API_BASE = '';

const DEBUG_UI = (localStorage.getItem('ZAGROS_DEBUG_UI') === '1');

function debugLog(...args) {
    if (DEBUG_UI) console.log(...args);
}

function debugError(...args) {
    if (DEBUG_UI) console.error(...args);
}

// Helper to get auth headers for all API requests
function getAuthHeaders() {
    const headers = {
        'Content-Type': 'application/json'
    };
    const token = localStorage.getItem('zargos_auth_token');
    if (token) {
        headers['X-Auth-Token'] = token;
    }
    return headers;
}

// Wrapper for fetch with auth
function authFetch(url, options = {}) {
    const token = localStorage.getItem('zargos_auth_token');
    if (!options.headers) {
        options.headers = {};
    }
    options.headers['Content-Type'] = 'application/json';
    if (token) {
        options.headers['X-Auth-Token'] = token;
    }
    return fetch(url, options);
}

// Helper function to clean/normalize IP addresses
function cleanIP(ip) {
    if (!ip) return null;
    // Remove any whitespace and common prefixes
    let cleaned = ip.trim();
    // Handle IPv4-mapped IPv6 addresses (::ffff:192.0.2.1 -> 192.0.2.1)
    if (cleaned.startsWith('::ffff:')) {
        cleaned = cleaned.substring(7);
    }

    function normalizeIPv6(input) {
        try {
            let v = String(input).trim().toLowerCase();
            if (!v.includes(':')) return null;
            if (v.includes('.')) return v; // leave IPv4-embedded formats as-is

            const parts = v.split('::');
            if (parts.length > 2) return null;
            const left = parts[0] ? parts[0].split(':').filter(Boolean) : [];
            const right = parts.length === 2 && parts[1] ? parts[1].split(':').filter(Boolean) : [];

            const hexOk = (h) => /^[0-9a-f]{1,4}$/.test(h);
            if (![...left, ...right].every(hexOk)) return null;

            const missing = 8 - (left.length + right.length);
            if (missing < 0) return null;

            const full = [...left, ...Array(missing).fill('0'), ...right]
                .map(h => parseInt(h, 16).toString(16));

            // Compress the longest run of zeros
            let bestStart = -1;
            let bestLen = 0;
            let curStart = -1;
            let curLen = 0;
            for (let i = 0; i < full.length; i++) {
                if (full[i] === '0') {
                    if (curStart === -1) curStart = i;
                    curLen++;
                } else {
                    if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
                    curStart = -1;
                    curLen = 0;
                }
            }
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }

            if (bestLen >= 2) {
                const before = full.slice(0, bestStart);
                const after = full.slice(bestStart + bestLen);
                const beforeStr = before.join(':');
                const afterStr = after.join(':');
                if (beforeStr && afterStr) return `${beforeStr}::${afterStr}`;
                if (beforeStr && !afterStr) return `${beforeStr}::`;
                if (!beforeStr && afterStr) return `::${afterStr}`;
                return '::';
            }

            return full.join(':');
        } catch (e) {
            return null;
        }
    }
    // Basic IPv4 validation pattern
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Pattern.test(cleaned)) {
        // Validate each octet is 0-255
        const octets = cleaned.split('.');
        const valid = octets.every(octet => {
            const num = parseInt(octet, 10);
            return num >= 0 && num <= 255;
        });
        if (valid) return cleaned;
    }
    // IPv6 basic check
    if (cleaned.includes(':')) {
        return normalizeIPv6(cleaned) || cleaned;
    }
    return null;
}

// DOM Elements
const discordIdInput = document.getElementById('discordIdInput');
const searchIdBtn = document.getElementById('searchIdBtn');
const loadingSection = document.getElementById('loadingSection');
const resultsSection = document.getElementById('resultsSection');
const noResults = document.getElementById('noResults');
const osintSection = document.getElementById('osintSection');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadFileStatus();
    setupEventListeners();
    setupMusicPlayer();
    setupDashboardNavigation();
});

function setActivePanel(panelId) {
    const panels = document.querySelectorAll('.app-panel');
    panels.forEach(p => p.classList.toggle('active', p.id === panelId));

    const nav = document.getElementById('sidebarNav');
    if (nav) {
        const items = nav.querySelectorAll('.nav-item[data-panel]');
        items.forEach(it => it.classList.toggle('active', it.dataset.panel === panelId));
    }

    if (panelId === 'panelAdmin') {
        try { loadAdminIhbarList(); } catch (e) {}
    }
}

function setupDashboardNavigation() {
    const nav = document.getElementById('sidebarNav');
    if (!nav) return;

    nav.addEventListener('click', (e) => {
        const btn = e.target.closest('.nav-item[data-panel]');
        if (!btn) return;
        setActivePanel(btn.dataset.panel);
    });
}

async function loadAdminIhbarList() {
    const body = document.getElementById('adminIhbarBody');
    if (!body) return;
    body.innerHTML = '<tr><td colspan="6" style="padding:10px; color: var(--text-muted);">Yükleniyor...</td></tr>';
    try {
        const res = await authFetch('/api/admin/ihbar/list?limit=50');
        if (res.status === 401) {
            body.innerHTML = '<tr><td colspan="6" style="padding:10px; color: var(--text-muted);">Giriş gerekli (401)</td></tr>';
            return;
        }
        const data = await res.json();
        if (!data.success) {
            body.innerHTML = '<tr><td colspan="6" style="padding:10px; color: var(--text-muted);">Yüklenemedi</td></tr>';
            return;
        }

        const tickets = Array.isArray(data.tickets) ? data.tickets : [];
        if (tickets.length === 0) {
            body.innerHTML = '<tr><td colspan="6" style="padding:10px; color: var(--text-muted);">Kayıt yok</td></tr>';
            return;
        }

        body.innerHTML = tickets.map(t => {
            const st = (t.status || 'NEW').toUpperCase();
            return `
                <tr>
                    <td style="padding:10px; border-bottom: 1px solid rgba(255,255,255,0.06);"><strong>${t.ticket_id}</strong></td>
                    <td style="padding:10px; border-bottom: 1px solid rgba(255,255,255,0.06);">${t.city || ''} / ${t.district || ''}</td>
                    <td style="padding:10px; border-bottom: 1px solid rgba(255,255,255,0.06);">${t.category || '-'}</td>
                    <td style="padding:10px; border-bottom: 1px solid rgba(255,255,255,0.06);">${t.urgency || '-'}</td>
                    <td style="padding:10px; border-bottom: 1px solid rgba(255,255,255,0.06);">${st}</td>
                    <td style="padding:10px; border-bottom: 1px solid rgba(255,255,255,0.06);">${t.created_at || '-'}</td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        body.innerHTML = '<tr><td colspan="6" style="padding:10px; color: var(--text-muted);">Bağlantı hatası</td></tr>';
    }
}

// Music Player Setup - Auto Play on Load
function setupMusicPlayer() {
    const musicToggle = document.getElementById('musicToggle');
    const bgMusic = document.getElementById('bgMusic');
    
    if (!musicToggle || !bgMusic) return;
    
    let isPlaying = true; // Start with playing state
    
    // Auto-start is handled by iframe src - just update UI
    musicToggle.classList.add('playing');
    musicToggle.innerHTML = '<i class="fas fa-volume-up"></i>';
    musicToggle.title = 'Müziği Durdur';
    
    musicToggle.addEventListener('click', () => {
        if (isPlaying) {
            // Stop playing
            bgMusic.src = '';
            musicToggle.classList.remove('playing');
            musicToggle.innerHTML = '<i class="fas fa-music"></i>';
            musicToggle.title = 'Müziği Başlat';
            isPlaying = false;
        } else {
            // Start playing
            const youtubeVideoId = 'xSuSHl8EBrw';
            bgMusic.src = `https://www.youtube.com/embed/${youtubeVideoId}?autoplay=1&loop=1&playlist=${youtubeVideoId}&mute=0&start=1`;
            musicToggle.classList.add('playing');
            musicToggle.innerHTML = '<i class="fas fa-volume-up"></i>';
            musicToggle.title = 'Müziği Durdur';
            isPlaying = true;
        }
    });
}

function setupEventListeners() {
    // Search tabs
    const discordTab = document.getElementById('discordTab');
    const tcTab = document.getElementById('tcTab');
    const discordPanel = document.getElementById('discordPanel');
    const tcPanel = document.getElementById('tcPanel');

    if (discordTab && tcTab) {
        discordTab.addEventListener('click', () => {
            discordTab.classList.add('active');
            tcTab.classList.remove('active');
            discordPanel.classList.add('active');
            tcPanel.classList.remove('active');
        });

        tcTab.addEventListener('click', () => {
            tcTab.classList.add('active');
            discordTab.classList.remove('active');
            tcPanel.classList.add('active');
            discordPanel.classList.remove('active');
        });
    }

    // Main search buttons
    searchIdBtn.addEventListener('click', performIntegratedSearch);
    discordIdInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performIntegratedSearch();
    });
    
    // TC Search buttons
    const tcInput = document.getElementById('tcInput');
    const searchTcBtn = document.getElementById('searchTcBtn');
    const searchTcFullBtn = document.getElementById('searchTcFullBtn');

    if (searchTcBtn) {
        searchTcBtn.addEventListener('click', performVesikaSearch);
    }
    if (searchTcFullBtn) {
        searchTcFullBtn.addEventListener('click', performFullTcSearch);
    }
    if (tcInput) {
        tcInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') performVesikaSearch();
        });
    }
    
    // Full Report button
    const fullReportBtn = document.getElementById('fullReportBtn');
    if (fullReportBtn) {
        fullReportBtn.addEventListener('click', () => {
            const discordId = discordIdInput.value.trim();
            if (!discordId) {
                alert('Lütfen bir Discord ID girin');
                return;
            }
            if (!/^\d{17,20}$/.test(discordId)) {
                alert('Geçersiz Discord ID formatı. ID 17-20 rakamdan oluşmalıdır.');
                return;
            }
            generateFullReport(discordId);
        });
    }

    // Upload section toggle
    const uploadHeader = document.getElementById('uploadHeader');
    const uploadPanel = document.getElementById('uploadPanel');
    if (uploadHeader) {
        uploadHeader.addEventListener('click', () => {
            uploadHeader.classList.toggle('active');
            uploadPanel.classList.toggle('active');
        });
    }

    // File upload
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    if (uploadArea && fileInput) {
        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--primary)';
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = 'var(--border)';
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--border)';
            if (e.dataTransfer.files.length > 0) {
                uploadFile(e.dataTransfer.files[0]);
            }
        });
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) uploadFile(e.target.files[0]);
        });
    }
}

async function loadStats() {
    try {
        const response = await authFetch(`${API_BASE}/api/stats`);
        const data = await response.json();
        const el = document.getElementById('totalRecords');
        if (el) el.textContent = data.total_records?.toLocaleString() || '-';
    } catch (error) {
        debugError('Stats load error:', error);
    }
}

async function loadFileStatus() {
    try {
        const response = await authFetch(`${API_BASE}/api/import/status`);
        const data = await response.json();
        const filesList = document.getElementById('filesList');
        if (!filesList) return;
        filesList.innerHTML = '';
        data.files.forEach(file => {
            const li = document.createElement('li');
            li.innerHTML = `
                <div class="file-info"><i class="fas fa-file-code"></i><span>${file.filename}</span></div>
                <span class="file-status">${file.exists ? '✓ Yüklü (' + file.size_mb + ' MB)' : '✗ Yok'}</span>
            `;
            filesList.appendChild(li);
        });
    } catch (error) {
        debugError('File status error:', error);
    }
}

// Vesika Sorgu fonksiyonu
async function performVesikaSearch() {
    const tcInput = document.getElementById('tcInput');
    const tcNo = tcInput ? tcInput.value.trim() : '';
    
    if (!tcNo) {
        alert('Lütfen bir TC Kimlik No girin');
        return;
    }
    
    if (!/^\d{11}$/.test(tcNo)) {
        alert('Geçersiz TC Kimlik No formatı. TC No 11 haneli olmalıdır.');
        return;
    }

    showLoading();
    hideResults();

    try {
        const response = await authFetch(`${API_BASE}/api/vesika`, {
            method: 'POST',
            body: JSON.stringify({ tc: tcNo })
        });
        
        const data = await response.json();
        
        if (data.error) {
            // Show detailed error if debug info is available
            let errorMsg = 'Vesika sorgu hatası: ' + data.error;
            if (data.debug_info && data.debug_info.errors) {
                debugError('Vesika API Errors:', data.debug_info.errors);
                errorMsg += '\n\nDetaylar:\n' + data.debug_info.errors.join('\n');
            }
            alert(errorMsg);
            return;
        }
        
        displayVesikaResults(data);
        
    } catch (error) {
        debugError('Vesika search error:', error);
        alert('Vesika sorgusu sırasında bir hata oluştu');
    } finally {
        hideLoading();
    }
}

// Full TC Search - Comprehensive search across all databases
async function performFullTcSearch() {
    const tcInput = document.getElementById('tcInput');
    const tcNo = tcInput ? tcInput.value.trim() : '';
    
    if (!tcNo) {
        alert('Lütfen bir TC Kimlik No girin');
        return;
    }
    
    if (!/^\d{11}$/.test(tcNo)) {
        alert('Geçersiz TC Kimlik No formatı. TC No 11 haneli olmalıdır.');
        return;
    }

    showLoading();
    hideResults();

    try {
        const response = await authFetch(`${API_BASE}/api/tc/full-search`, {
            method: 'POST',
            body: JSON.stringify({ tc: tcNo })
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert('TC sorgu hatası: ' + data.error);
            return;
        }
        
        displayTcFullResults(data);
        
    } catch (error) {
        debugError('Full TC search error:', error);
        alert('TC sorgusu sırasında bir hata oluştu');
    } finally {
        hideLoading();
    }
}

// Vesika sonuçlarını göster
function displayVesikaResults(data) {
    hideLoading();
    noResults.classList.remove('active');
    resultsSection.classList.add('active');

    const currentDate = new Date().toLocaleString('tr-TR');
    const dateEl = document.getElementById('investigationDate');
    if (dateEl) dateEl.textContent = currentDate;

    // Subject Profile - TC No göster
    const subjectIdEl = document.getElementById('subjectId');
    if (subjectIdEl) subjectIdEl.textContent = `TC: ${data.tc}`;

    // Status badge güncelle
    const statusBadge = document.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.className = 'status-badge found';
        statusBadge.textContent = 'VESIKA BULUNDU';
    }

    // Vesika sonuçlarını göster - dinamik alanlar
    const summaryGrid = document.getElementById('summaryGrid');
    if (summaryGrid) {
        // Build vesika rows dynamically based on available data
        let vesikaRows = '';
        
        // TC No
        vesikaRows += `
            <div class="vesika-row">
                <span class="vesika-label">TC Kimlik No:</span>
                <span class="vesika-value">${data.tc}</span>
            </div>
        `;
        
        // İsim
        if (data.isim) {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">İsim:</span>
                    <span class="vesika-value">${data.isim}</span>
                </div>
            `;
        }
        
        // Soyisim
        if (data.soyisim) {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Soyisim:</span>
                    <span class="vesika-value">${data.soyisim}</span>
                </div>
            `;
        }
        
        // Doğum Tarihi
        if (data.dogum_tarihi && data.dogum_tarihi !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Doğum Tarihi:</span>
                    <span class="vesika-value">${data.dogum_tarihi}</span>
                </div>
            `;
        }
        
        // Cinsiyet
        if (data.cinsiyet && data.cinsiyet !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Cinsiyet:</span>
                    <span class="vesika-value">${data.cinsiyet}</span>
                </div>
            `;
        }
        
        // Anne Adı
        if (data.anne_adi && data.anne_adi !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Anne Adı:</span>
                    <span class="vesika-value">${data.anne_adi}</span>
                </div>
            `;
        }
        
        // Baba Adı
        if (data.baba_adi && data.baba_adi !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Baba Adı:</span>
                    <span class="vesika-value">${data.baba_adi}</span>
                </div>
            `;
        }
        
        // Nüfus İl
        if (data.nufus_il && data.nufus_il !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Nüfus İl:</span>
                    <span class="vesika-value">${data.nufus_il}</span>
                </div>
            `;
        }
        
        // Nüfus İlçe
        if (data.nufus_ilce && data.nufus_ilce !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Nüfus İlçe:</span>
                    <span class="vesika-value">${data.nufus_ilce}</span>
                </div>
            `;
        }
        
        // Yapsavun format - Okul bilgileri
        if (data.okul_turu && data.okul_turu !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Okul Türü:</span>
                    <span class="vesika-value">${data.okul_turu}</span>
                </div>
            `;
        }
        
        if (data.mezun_okul && data.mezun_okul !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Mezun Okul:</span>
                    <span class="vesika-value">${data.mezun_okul}</span>
                </div>
            `;
        }
        
        if (data.alan && data.alan !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Alan:</span>
                    <span class="vesika-value">${data.alan}</span>
                </div>
            `;
        }
        
        if (data.diploma_puan && data.diploma_puan !== 'Bilinmiyor') {
            vesikaRows += `
                <div class="vesika-row">
                    <span class="vesika-label">Diploma Puanı:</span>
                    <span class="vesika-value">${data.diploma_puan}</span>
                </div>
            `;
        }
        
        // Vesika fotoğrafı
        let vesikaImage = '';
        if (data.image) {
            vesikaImage = `
                <div class="vesika-photo" style="margin-top: 15px; text-align: center;">
                    <img src="${data.image}" alt="Vesika" style="max-width: 150px; border-radius: 8px; border: 2px solid var(--primary);" onerror="this.style.display='none'">
                </div>
            `;
        }
        
        summaryGrid.innerHTML = `
            <div class="summary-card vesika-info" style="grid-column: 1 / -1;">
                <div class="summary-icon"><i class="fas fa-id-card"></i></div>
                <div class="summary-content">
                    <h3>VESIKA BİLGİLERİ</h3>
                    <div class="vesika-details">
                        ${vesikaRows}
                    </div>
                    ${vesikaImage}
                </div>
            </div>
        `;
    }

    // Database sonuçlarını gizle (vesika sorgusunda yok)
    const dbResults = document.getElementById('dbResults');
    if (dbResults) dbResults.style.display = 'none';

    // OSINT section'ı gizle
    if (osintSection) osintSection.classList.remove('active');
}

// Full TC Search Results Display
function displayTcFullResults(data) {
    hideLoading();
    noResults.classList.remove('active');
    resultsSection.classList.add('active');

    const currentDate = new Date().toLocaleString('tr-TR');
    const dateEl = document.getElementById('investigationDate');
    if (dateEl) dateEl.textContent = currentDate;

    // Subject Profile - TC No göster
    const subjectIdEl = document.getElementById('subjectId');
    if (subjectIdEl) subjectIdEl.textContent = `TC: ${data.tc}`;

    // Status badge güncelle
    const statusBadge = document.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.className = 'status-badge found';
        statusBadge.textContent = 'TC KAYIT BULUNDU';
    }

    // Build comprehensive results HTML
    const summaryGrid = document.getElementById('summaryGrid');
    if (summaryGrid) {
        let html = '';
        
        // Vesika Photo Card (if available)
        if (data.vesika && data.vesika.image) {
            html += `
                <div class="summary-card vesika-photo-card" style="grid-column: 1 / -1;">
                    <div class="summary-icon"><i class="fas fa-portrait"></i></div>
                    <div class="summary-content">
                        <h3>VESIKA FOTOĞRAFI</h3>
                        <div class="vesika-photo-container">
                            <img src="${data.vesika.image}" alt="Vesika" class="vesika-photo" onerror="this.style.display='none'">
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Vesika Info Card
        if (data.vesika) {
            html += `
                <div class="summary-card vesika-info" style="grid-column: 1 / -1;">
                    <div class="summary-icon"><i class="fas fa-id-card"></i></div>
                    <div class="summary-content">
                        <h3>VESIKA BİLGİLERİ</h3>
                        <table class="tc-results-table">
                            <thead>
                                <tr>
                                    <th>TC</th>
                                    <th>Adı</th>
                                    <th>Soyadı</th>
                                    <th>Durum</th>
                                    <th>Okul Türü</th>
                                    <th>Alan</th>
                                    <th>Şube</th>
                                    <th>Okul No</th>
                                    <th>Mezun Okul</th>
                                    <th>Diploma Puanı</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>${data.vesika.tc || data.tc}</td>
                                    <td>${data.vesika.isim || '-'}</td>
                                    <td>${data.vesika.soyisim || '-'}</td>
                                    <td>${data.vesika.durum || '-'}</td>
                                    <td>${data.vesika.okul_turu || '-'}</td>
                                    <td>${data.vesika.alan || '-'}</td>
                                    <td>${data.vesika.sube || '-'}</td>
                                    <td>${data.vesika.okul_no || '-'}</td>
                                    <td>${data.vesika.mezun_okul || '-'}</td>
                                    <td>${data.vesika.diploma_puan || '-'}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }
        
        // Database Results Summary
        if (data.database_results) {
            const dbResults = data.database_results;
            html += `
                <div class="summary-card db-summary" style="grid-column: 1 / -1;">
                    <div class="summary-icon"><i class="fas fa-database"></i></div>
                    <div class="summary-content">
                        <h3>VERİTABANI SONUÇLARI</h3>
                        <div class="vesika-details">
                            <div class="vesika-row">
                                <span class="vesika-label">Foxnet (Zagros Alpha):</span>
                                <span class="vesika-value">${dbResults.foxnet?.length || 0} kayıt</span>
                            </div>
                            <div class="vesika-row">
                                <span class="vesika-label">Five SQL (Zagros Beta):</span>
                                <span class="vesika-value">${dbResults.five_sql?.length || 0} kayıt</span>
                            </div>
                            <div class="vesika-row">
                                <span class="vesika-label">MariaDB (Zagros Gamma):</span>
                                <span class="vesika-value">${dbResults.mariadb?.length || 0} kayıt</span>
                            </div>
                            <div class="vesika-row">
                                <span class="vesika-label">Toplam Kayıt:</span>
                                <span class="vesika-value" style="color: var(--success);">${dbResults.total_records || 0}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Associated Emails
        if (data.emails && data.emails.length > 0) {
            html += `
                <div class="summary-card emails" style="grid-column: 1 / -1;">
                    <div class="summary-icon"><i class="fas fa-envelope"></i></div>
                    <div class="summary-content">
                        <h3>İLİŞKİLİ E-POSTA ADRESLERİ</h3>
                        <ul class="emails-list">
                            ${data.emails.map(email => `<li class="email-value">${email}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }
        
        // Associated IPs
        if (data.ips && data.ips.length > 0) {
            html += `
                <div class="summary-card ips" style="grid-column: 1 / -1;">
                    <div class="summary-icon"><i class="fas fa-map-marker-alt"></i></div>
                    <div class="summary-content">
                        <h3>İLİŞKİLİ IP ADRESLERİ</h3>
                        <ul class="ips-list">
                            ${data.ips.map(ip => {
                                const cip = cleanIP(ip) || ip;
                                return `<li class="ip-value">${cip}</li>`;
                            }).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }
        
        summaryGrid.innerHTML = html;
    }

    // Show database details if available
    const dbResults = document.getElementById('dbResults');
    if (dbResults && data.database_results) {
        dbResults.style.display = 'block';
        displayDbRecords('foxnet', data.database_results.foxnet);
        displayDbRecords('fiveSql', data.database_results.five_sql);
        displayDbRecords('mariadb', data.database_results.mariadb);
    }

    // OSINT section for email analysis
    if (osintSection && data.emails && data.emails.length > 0) {
        osintSection.classList.add('active');
    }
}

// Main Integrated Search
async function performIntegratedSearch() {
    const discordId = discordIdInput.value.trim();
    
    if (!discordId) {
        alert('Lütfen bir Discord ID girin');
        return;
    }
    
    if (!/^\d{17,20}$/.test(discordId)) {
        alert('Geçersiz Discord ID formatı. ID 17-20 rakamdan oluşmalıdır.');
        return;
    }

    showLoading();
    hideResults();

    try {
        // Store last searched ID for UI fallbacks (e.g. Findcord responses without UserInfo)
        window.__lastDiscordId = discordId;

        // Step 1: Search by ID
        const idResponse = await authFetch(`${API_BASE}/api/search`, {
            method: 'POST',
            body: JSON.stringify({ discord_id: discordId })
        });
        const idData = await idResponse.json();
        debugLog('[DEBUG] API Response - idData:', idData);
        debugLog('[DEBUG] Findcord data in response:', idData.findcord);

        if (!idData.found) {
            showNoResults();
            return;
        }

        // Step 2: For found emails, get OSINT data (auto for up to 3 emails)
        let osintData = null;
        if (idData.emails && idData.emails.length > 0) {
            const emailsToCheck = idData.emails.slice(0, 3);
            const reports = [];
            for (const email of emailsToCheck) {
                try {
                    const osintResponse = await authFetch(`${API_BASE}/api/osint/email`, {
                        method: 'POST',
                        body: JSON.stringify({ email })
                    });
                    const report = await osintResponse.json();
                    reports.push({ email, report, error: report?.error || null });
                } catch (e) {
                    debugError('OSINT fetch error:', e);
                    reports.push({ email, report: null, error: String(e) });
                }
            }
            osintData = { reports };
        }

        // Step 3: Display all results together
        displayIntegratedResults(idData, osintData);

    } catch (error) {
        debugError('Search error:', error);
        alert('Arama sırasında bir hata oluştu');
    } finally {
        hideLoading();
    }
}

function displayIntegratedResults(idData, osintData) {
    hideLoading();
    noResults.classList.remove('active');
    resultsSection.classList.add('active');

    try { setActivePanel('panelResults'); } catch (e) {}

    const currentDate = new Date().toLocaleString('tr-TR');
    const dateEl = document.getElementById('investigationDate');
    if (dateEl) dateEl.textContent = currentDate;

    // Subject Profile
    const subjectIdEl = document.getElementById('subjectId');
    if (subjectIdEl) subjectIdEl.textContent = idData.discord_id || 'Bilinmiyor';

    // Discord Profile - Priority: Findcord > Database > Default
    const discordAvatar = document.getElementById('discordAvatar');
    const discordUsername = document.getElementById('discordUsername');
    const profileAvatar = document.querySelector('.profile-avatar');
    
    // Check for findcord data first
    const findcordData = idData.findcord?.data || {};
    const hasFindcordData = idData.findcord?.success && findcordData.username;
    
    if (discordAvatar && discordUsername) {
        if (hasFindcordData && findcordData.avatar) {
            // Use findcord avatar
            discordAvatar.src = `https://cdn.discordapp.com/avatars/${findcordData.id}/${findcordData.avatar}.png`;
            discordAvatar.style.display = 'block';
        } else {
            // Generate Discord avatar URL based on user ID
            const avatarIndex = parseInt(idData.discord_id) % 5;
            discordAvatar.src = `https://cdn.discordapp.com/embed/avatars/${avatarIndex}.png`;
            discordAvatar.style.display = 'block';
        }
        
        // Priority for username: Findcord > Database > ID
        if (hasFindcordData && findcordData.username) {
            discordUsername.textContent = findcordData.username + (findcordData.discriminator ? `#${findcordData.discriminator}` : '');
        } else if (idData.usernames && idData.usernames.length > 0) {
            discordUsername.textContent = idData.usernames[0];
        } else {
            discordUsername.textContent = `ID: ${idData.discord_id}`;
        }
    }

    // Update subject profile avatar with findcord data if available
    if (profileAvatar && hasFindcordData && findcordData.avatar) {
        profileAvatar.innerHTML = `<img src="https://cdn.discordapp.com/avatars/${findcordData.id}/${findcordData.avatar}.png" style="width: 80px; height: 80px; border-radius: 50%; border: 3px solid var(--primary);" onerror="this.innerHTML='<i class=\\'fas fa-user\\'></i>'">`;
    } else if (profileAvatar) {
        profileAvatar.innerHTML = '<i class="fas fa-user"></i>';
    }

    const statusBadge = document.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.className = 'status-badge found';
        statusBadge.textContent = 'KAYIT BULUNDU';
    }

    // Emails
    const emailsList = document.getElementById('emailsList');
    if (emailsList) {
        emailsList.innerHTML = '';
        if (idData.emails && idData.emails.length > 0) {
            idData.emails.forEach(email => {
                const li = document.createElement('li');
                li.textContent = email;
                li.className = 'email-value';
                emailsList.appendChild(li);
            });
        } else {
            emailsList.innerHTML = '<li class="no-data">E-posta bulunamadı</li>';
        }
    }

    // IPs with location info
    const ipsList = document.getElementById('ipsList');
    const ipInfoGrid = document.getElementById('ipInfoGrid');
    
    if (ipsList) {
        ipsList.innerHTML = '';
        if (idData.ips && idData.ips.length > 0) {
            idData.ips.forEach(ip => {
                const clean = cleanIP(ip) || ip;
                const li = document.createElement('li');
                li.className = 'ip-value';
                li.style.cssText = 'display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: rgba(255,255,255,0.05); border-radius: 6px; margin-bottom: 6px;';
                li.innerHTML = `
                    <span style="font-family: monospace; color: #60a5fa;">${clean}</span>
                    <span class="ip-location" style="color: #9ca3af; font-size: 12px; margin-left: 10px;">Yükleniyor...</span>
                `;
                ipsList.appendChild(li);
                
                // Fetch location for each IP
                fetchLocationForIP(clean, li.querySelector('.ip-location'));
            });
            
            // Get IP info for first IP
            if (ipInfoGrid) {
                const first = cleanIP(idData.ips[0]) || idData.ips[0];
                fetchIPInfo(first);
            }
        } else {
            ipsList.innerHTML = '<li class="no-data">IP adresi bulunamadı</li>';
            if (ipInfoGrid) ipInfoGrid.innerHTML = '<div class="ip-info-item"><span>IP bilgisi bulunamadı</span></div>';
        }
    }

    // Usernames
    const usernamesList = document.getElementById('usernamesList');
    if (usernamesList) {
        usernamesList.innerHTML = '';
        if (idData.usernames && idData.usernames.length > 0) {
            idData.usernames.forEach(username => {
                const li = document.createElement('li');
                li.textContent = username;
                usernamesList.appendChild(li);
            });
        } else {
            usernamesList.innerHTML = '<li class="no-data">Kullanıcı adı bulunamadı</li>';
        }
    }

    // ===== FINDCORD RESULTS =====
    displayFindcordResults(idData.findcord);

    // Database Records
    displayDbRecords('foxnet', idData.foxnet);
    displayDbRecords('fiveSql', idData.five_sql);
    displayDbRecords('mariadb', idData.mariadb);

    // OSINT Section (if data available)
    if (osintData) {
        displayOSINTResults(osintData);
    } else {
        if (osintSection) osintSection.classList.remove('active');
    }
}

// Display Findcord.com API Results
function displayFindcordResults(findcordData) {
    debugLog('[DEBUG] displayFindcordResults called with:', findcordData);
    
    // Check if findcord section exists, if not create it
    let findcordSection = document.getElementById('findcordSection');
    
    // Also handle the new findcord results section
    const findcordResultsSection = document.getElementById('findcordResultsSection');
    const findcordDbInfo = document.getElementById('findcordDbInfo');
    
    debugLog('[DEBUG] findcordResultsSection:', findcordResultsSection);
    debugLog('[DEBUG] findcordDbInfo:', findcordDbInfo);
    debugLog('[DEBUG] findcordSection:', findcordSection);
    
    if (!findcordData || !findcordData.success) {
        debugLog('[DEBUG] No findcord data or success is false:', findcordData);
        // Hide section if no data
        if (findcordSection) findcordSection.style.display = 'none';
        if (findcordResultsSection) findcordResultsSection.style.display = 'none';
        return;
    }
    
    debugLog('[DEBUG] Findcord data success, proceeding to display');
    
    // Show the new findcord results section
    if (findcordResultsSection) {
        findcordResultsSection.style.display = 'block';
        debugLog('[DEBUG] findcordResultsSection shown');
    }
    
    // Create section if doesn't exist
    if (!findcordSection) {
        const summaryGrid = document.getElementById('summaryGrid');
        if (!summaryGrid) {
            debugError('[DEBUG] summaryGrid not found!');
            return;
        }
        
        findcordSection = document.createElement('div');
        findcordSection.id = 'findcordSection';
        findcordSection.className = 'summary-card findcord-info';
        findcordSection.style.cssText = 'grid-column: 1 / -1; margin-top: 20px;';
        
        // Insert after discord profile section
        summaryGrid.insertBefore(findcordSection, summaryGrid.firstChild);
        debugLog('[DEBUG] findcordSection created and inserted');
    }
    
    findcordSection.style.display = 'block';
    
    const data = findcordData.data || {};

    // Normalize Findcord API schema differences
    const userInfo = data.UserInfo || data.userInfo || {};
    const lastDiscordId = window.__lastDiscordId ? String(window.__lastDiscordId) : '';

    // Some Findcord responses don't include UserInfo; derive best-effort identity from other fields
    const guildsForIdentity = (data.Guilds || data.guilds || []);
    const firstGuild = Array.isArray(guildsForIdentity) && guildsForIdentity.length > 0 ? guildsForIdentity[0] : null;
    const fallbackUsername =
        (Array.isArray(data.displayNames) && data.displayNames.length > 0 && (data.displayNames[0].name || data.displayNames[0].displayName)) ||
        (data.GuildStaff && Array.isArray(data.GuildStaff) && data.GuildStaff[0] && (data.GuildStaff[0].displayName || data.GuildStaff[0].name)) ||
        (data.TopName && (data.TopName.name || data.TopName.displayName || data.TopName.username)) ||
        (firstGuild && (firstGuild.displayName || firstGuild.DisplayName || firstGuild.username || firstGuild.UserName)) ||
        null;
    const normalized = {
        username: userInfo.username || userInfo.Username || userInfo.userName || data.username || data.Username || data.name || fallbackUsername,
        discriminator: userInfo.discriminator || userInfo.Discriminator || data.discriminator || null,
        id: String(
            userInfo.id || userInfo.Id || userInfo.userId || userInfo.user_id || userInfo.discord_id || data.id || data.user_id || data.discord_id || ''
        ),
        avatar: userInfo.avatar || userInfo.Avatar || data.avatar || null,
        email: userInfo.email || userInfo.Email || data.email || null,
        verified: (userInfo.verified !== undefined ? userInfo.verified : (data.verified !== undefined ? data.verified : undefined)),
        locale: userInfo.locale || data.locale || null,
        guilds: data.Guilds || data.guilds || data.guild || [],
        connections: userInfo.connections || data.connections || [],
        whereNow: data.WhereNow || data.whereNow || null,
        raw: data
    };

    if (!normalized.id) {
        normalized.id = lastDiscordId;
    }
    debugLog('[DEBUG] Findcord data object:', data);
    debugLog('[DEBUG] Findcord data keys:', Object.keys(data));
    debugLog('[DEBUG] Username:', normalized.username, '| ID:', normalized.id);
    debugLog('[DEBUG] Looking for alternative keys:');
    debugLog('[DEBUG] - data.Username:', data.Username);
    debugLog('[DEBUG] - data.user_id:', data.user_id);
    debugLog('[DEBUG] - data.discord_id:', data.discord_id);
    debugLog('[DEBUG] - data.name:', data.name);
    debugLog('[DEBUG] - data.global_name:', data.global_name);
    debugLog('[DEBUG] - data.display_name:', data.display_name);
    debugLog('[DEBUG] Full data JSON:', JSON.stringify(data, null, 2));
    
    // Build clean table HTML for findcord data
    let html = `
        <div class="summary-icon"><i class="fab fa-discord" style="color: #5865F2;"></i></div>
        <div class="summary-content">
            <h3 style="color: #5865F2; font-family: Arial, sans-serif;"><i class="fas fa-search"></i> FINDCORD API SONUÇLARI</h3>
            <div class="findcord-box" style="background: #ffffff; border: 2px solid #5865F2; border-radius: 8px; padding: 20px; margin-top: 15px; font-family: Arial, sans-serif;">
                <table style="width: 100%; border-collapse: collapse; font-size: 14px; color: #333;">
                    <tbody>
    `;
    
    // Display key fields from findcord data in table rows
    if (normalized.username) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; width: 30%; font-weight: 600; color: #5865F2;">Kullanıcı Adı:</td>
                <td style="padding: 12px 15px; color: #333;">${normalized.username}</td>
            </tr>
        `;
    }
    
    if (normalized.discriminator) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Discriminator:</td>
                <td style="padding: 12px 15px; color: #333;">#${normalized.discriminator}</td>
            </tr>
        `;
    }
    
    if (normalized.id) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Discord ID:</td>
                <td style="padding: 12px 15px; color: #333; font-family: monospace;">${normalized.id}</td>
            </tr>
        `;
    }
    
    if (normalized.avatar && normalized.id) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: middle;">Avatar:</td>
                <td style="padding: 12px 15px;">
                    <img src="https://cdn.discordapp.com/avatars/${normalized.id}/${normalized.avatar}.png" 
                         style="width: 64px; height: 64px; border-radius: 50%; border: 2px solid #5865F2;"
                         onerror="this.style.display='none'" alt="Avatar">
                </td>
            </tr>
        `;
    }
    
    if (normalized.email) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">E-posta:</td>
                <td style="padding: 12px 15px; color: #333;">${normalized.email}</td>
            </tr>
        `;
    }
    
    if (normalized.verified !== undefined) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Doğrulanmış:</td>
                <td style="padding: 12px 15px; color: ${normalized.verified ? '#22c55e' : '#ef4444'}; font-weight: 500;">
                    ${normalized.verified ? 'Evet' : 'Hayır'}
                </td>
            </tr>
        `;
    }
    
    if (normalized.locale) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Dil/Bölge:</td>
                <td style="padding: 12px 15px; color: #333;">${normalized.locale}</td>
            </tr>
        `;
    }
    
    if (data.flags !== undefined) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Bayraklar:</td>
                <td style="padding: 12px 15px; color: #333; font-family: monospace;">${data.flags}</td>
            </tr>
        `;
    }
    
    // If there's a guilds/mutual servers list
    if (normalized.guilds && Array.isArray(normalized.guilds) && normalized.guilds.length > 0) {
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Sunucular (${normalized.guilds.length}):</td>
                <td style="padding: 12px 15px;">
                    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                        ${normalized.guilds.map(guild => `
                            <span style="background: #f0f2ff; border: 1px solid #5865F2; padding: 4px 12px; border-radius: 12px; font-size: 12px; color: #333;">
                                ${guild.GuildName || guild.name || guild.GuildId || guild.id || 'Bilinmiyor'}
                            </span>
                        `).join('')}
                    </div>
                </td>
            </tr>
        `;
    }
    
    // If there's connections data
    if (normalized.connections && Array.isArray(normalized.connections) && normalized.connections.length > 0) {
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Bağlantılar:</td>
                <td style="padding: 12px 15px;">
                    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                        ${normalized.connections.map(conn => `
                            <span style="background: #f0f2ff; border: 1px solid #5865F2; padding: 4px 12px; border-radius: 12px; font-size: 12px; color: #333;">
                                ${conn.name || conn.id || conn.type}
                            </span>
                        `).join('')}
                    </div>
                </td>
            </tr>
        `;
    }

    const messageFriends = data.MessageFriends || data.messageFriends || [];
    if (Array.isArray(messageFriends) && messageFriends.length > 0) {
        const top = messageFriends.slice(0, 10);
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Mesaj Arkadaşları:</td>
                <td style="padding: 12px 15px;">
                    <div style="display: flex; flex-direction: column; gap: 6px;">
                        ${top.map(f => `
                            <div style="display: flex; justify-content: space-between; gap: 12px; padding: 6px 10px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fafafa;">
                                <span style="color: #111827;">${f.username || f.UserName || f.name || f.DisplayName || f.userId || f.UserId || 'Bilinmiyor'}</span>
                                <span style="color: #6b7280; font-family: monospace;">${f.messageCount || f.MessageCount || f.count || ''}</span>
                            </div>
                        `).join('')}
                    </div>
                </td>
            </tr>
        `;
    }

    const voiceFriends = data.VoiceFrends || data.VoiceFriends || data.voiceFriends || [];
    if (Array.isArray(voiceFriends) && voiceFriends.length > 0) {
        const top = voiceFriends.slice(0, 10);
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Ses Arkadaşları:</td>
                <td style="padding: 12px 15px;">
                    <div style="display: flex; flex-direction: column; gap: 6px;">
                        ${top.map(f => `
                            <div style="display: flex; justify-content: space-between; gap: 12px; padding: 6px 10px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fafafa;">
                                <span style="color: #111827;">${f.username || f.UserName || f.name || f.DisplayName || f.userId || f.UserId || 'Bilinmiyor'}</span>
                                <span style="color: #6b7280; font-family: monospace;">${f.voiceTimeText || f.VoiceTimeText || f.voiceMinutes || f.VoiceMinutes || f.totalMinutes || ''}</span>
                            </div>
                        `).join('')}
                    </div>
                </td>
            </tr>
        `;
    }

    const whereNow = normalized.whereNow;
    if (whereNow && typeof whereNow === 'object') {
        const guildName = whereNow.GuildName || whereNow.guildName || whereNow.guild || '';
        const channelName = whereNow.ChannelName || whereNow.channelName || whereNow.channel || '';
        const state = whereNow.State || whereNow.state || whereNow.status || '';
        const text = [guildName, channelName].filter(Boolean).join(' / ');
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Şu an:</td>
                <td style="padding: 12px 15px;">
                    <div style="padding: 10px 12px; border: 1px solid #e5e7eb; border-radius: 10px; background: #f8fafc;">
                        <div style="color: #111827; font-weight: 600;">${text || 'Bilinmiyor'}</div>
                        ${state ? `<div style="color: #6b7280; margin-top: 2px;">${state}</div>` : ''}
                    </div>
                </td>
            </tr>
        `;
    }
    
    html += `
                    </tbody>
                </table>
                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #e0e0e0; font-size: 11px; color: #666; text-align: center;">
                    <i class="fas fa-info-circle"></i> Bu veriler findcord.com API'sinden alınmıştır.
                </div>
            </div>
        </div>
    `;
    
    findcordSection.innerHTML = html;
    
    // Also populate the new findcord results section with same table format
    if (findcordDbInfo) {
        let dbHtml = `
            <div class="findcord-box" style="background: #ffffff; border: 2px solid #5865F2; border-radius: 8px; padding: 20px; font-family: Arial, sans-serif;">
                <table style="width: 100%; border-collapse: collapse; font-size: 14px; color: #333;">
                    <tbody>
        `;
        
        if (normalized.username) {
            dbHtml += `
                <tr style="border-bottom: 1px solid #e0e0e0;">
                    <td style="padding: 12px 15px; width: 30%; font-weight: 600; color: #5865F2;">Kullanıcı Adı</td>
                    <td style="padding: 12px 15px; color: #333;">${normalized.username}</td>
                </tr>
            `;
        }
        
        if (normalized.discriminator) {
            dbHtml += `
                <tr style="border-bottom: 1px solid #e0e0e0;">
                    <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Discriminator</td>
                    <td style="padding: 12px 15px; color: #333;">#${normalized.discriminator}</td>
                </tr>
            `;
        }
        
        if (normalized.email) {
            dbHtml += `
                <tr style="border-bottom: 1px solid #e0e0e0;">
                    <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">E-posta</td>
                    <td style="padding: 12px 15px; color: #333;">${normalized.email}</td>
                </tr>
            `;
        }
        
        if (normalized.verified !== undefined) {
            dbHtml += `
                <tr style="border-bottom: 1px solid #e0e0e0;">
                    <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Doğrulanmış</td>
                    <td style="padding: 12px 15px; color: ${normalized.verified ? '#22c55e' : '#ef4444'}; font-weight: 500;">
                        ${normalized.verified ? 'Evet' : 'Hayır'}
                    </td>
                </tr>
            `;
        }
        
        if (normalized.locale) {
            dbHtml += `
                <tr style="border-bottom: 1px solid #e0e0e0;">
                    <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Dil/Bölge</td>
                    <td style="padding: 12px 15px; color: #333;">${normalized.locale}</td>
                </tr>
            `;
        }
        
        // Add guilds info if available
        if (normalized.guilds && Array.isArray(normalized.guilds) && normalized.guilds.length > 0) {
            dbHtml += `
                <tr>
                    <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Sunucular (${normalized.guilds.length})</td>
                    <td style="padding: 12px 15px;">
                        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                            ${normalized.guilds.map(guild => `
                                <span style="background: #f0f2ff; border: 1px solid #5865F2; padding: 4px 12px; border-radius: 12px; font-size: 12px; color: #333;">
                                    ${guild.GuildName || guild.name || 'Bilinmeyen'}
                                </span>
                            `).join('')}
                        </div>
                    </td>
                </tr>
            `;
        }

        const messageFriends2 = data.MessageFriends || data.messageFriends || [];
        if (Array.isArray(messageFriends2) && messageFriends2.length > 0) {
            const top = messageFriends2.slice(0, 10);
            dbHtml += `
                <tr>
                    <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Mesaj Arkadaşları</td>
                    <td style="padding: 12px 15px;">
                        <div style="display: flex; flex-direction: column; gap: 6px;">
                            ${top.map(f => `
                                <div style="display: flex; justify-content: space-between; gap: 12px; padding: 6px 10px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fafafa;">
                                    <span style="color: #111827;">${f.username || f.UserName || f.name || f.DisplayName || f.userId || f.UserId || 'Bilinmiyor'}</span>
                                    <span style="color: #6b7280; font-family: monospace;">${f.messageCount || f.MessageCount || f.count || ''}</span>
                                </div>
                            `).join('')}
                        </div>
                    </td>
                </tr>
            `;
        }

        const voiceFriends2 = data.VoiceFrends || data.VoiceFriends || data.voiceFriends || [];
        if (Array.isArray(voiceFriends2) && voiceFriends2.length > 0) {
            const top = voiceFriends2.slice(0, 10);
            dbHtml += `
                <tr>
                    <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Ses Arkadaşları</td>
                    <td style="padding: 12px 15px;">
                        <div style="display: flex; flex-direction: column; gap: 6px;">
                            ${top.map(f => `
                                <div style="display: flex; justify-content: space-between; gap: 12px; padding: 6px 10px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fafafa;">
                                    <span style="color: #111827;">${f.username || f.UserName || f.name || f.DisplayName || f.userId || f.UserId || 'Bilinmiyor'}</span>
                                    <span style="color: #6b7280; font-family: monospace;">${f.voiceTimeText || f.VoiceTimeText || f.voiceMinutes || f.VoiceMinutes || f.totalMinutes || ''}</span>
                                </div>
                            `).join('')}
                        </div>
                    </td>
                </tr>
            `;
        }

        const whereNow2 = normalized.whereNow;
        if (whereNow2 && typeof whereNow2 === 'object') {
            const guildName = whereNow2.GuildName || whereNow2.guildName || whereNow2.guild || '';
            const channelName = whereNow2.ChannelName || whereNow2.channelName || whereNow2.channel || '';
            const state = whereNow2.State || whereNow2.state || whereNow2.status || '';
            const text = [guildName, channelName].filter(Boolean).join(' / ');
            dbHtml += `
                <tr>
                    <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Şu an</td>
                    <td style="padding: 12px 15px;">
                        <div style="padding: 10px 12px; border: 1px solid #e5e7eb; border-radius: 10px; background: #f8fafc;">
                            <div style="color: #111827; font-weight: 600;">${text || 'Bilinmiyor'}</div>
                            ${state ? `<div style="color: #6b7280; margin-top: 2px;">${state}</div>` : ''}
                        </div>
                    </td>
                </tr>
            `;
        }
        
        dbHtml += `
                    </tbody>
                </table>
            </div>
        `;
        
        findcordDbInfo.innerHTML = dbHtml;
    }
    
    // Auto-load Discord friends after displaying results
    if (window.loadDiscordFriends && window.__lastDiscordId) {
        // Small delay to ensure UI is ready
        setTimeout(() => {
            window.loadDiscordFriends();
        }, 500);
    }
}

// Display Database Records
function displayDbRecords(dbName, records) {
    const countEl = document.getElementById(`${dbName}Count`);
    const recordsEl = document.getElementById(`${dbName}Records`);
    const sectionEl = document.getElementById(`${dbName}Section`);

    if (!countEl || !recordsEl || !sectionEl) {
        return;
    }

    // Ensure records is an array
    const recordsArray = Array.isArray(records) ? records : [];
    
    // Filter out duplicate records based on email + IP combination
    const uniqueRecords = [];
    const seen = new Set();
    
    recordsArray.forEach(record => {
        if (!record || typeof record !== 'object') return;
        const key = `${record.email || ''}|${record.ip || ''}|${record.discord_id || ''}`;
        if (!seen.has(key)) {
            seen.add(key);
            uniqueRecords.push(record);
        }
    });

    countEl.textContent = `${uniqueRecords.length} kayıt`;
    recordsEl.innerHTML = '';

    if (uniqueRecords.length === 0) {
        sectionEl.style.display = 'none';
        return;
    }

    sectionEl.style.display = 'block';

    uniqueRecords.forEach(record => {
        const item = document.createElement('div');
        item.className = 'record-item';
        
        // Create fields based on available data
        let fieldsHTML = '';
        
        if (record.email) {
            fieldsHTML += `
                <div class="record-field">
                    <label>Email</label>
                    <span class="email-value">${record.email}</span>
                </div>
            `;
        }
        
        if (record.ip) {
            const cleanIp = cleanIP(record.ip);
            if (cleanIp) {
                fieldsHTML += `
                    <div class="record-field">
                        <label>IP Adresi</label>
                        <span class="ip-value" title="${cleanIp}">${cleanIp}</span>
                    </div>
                `;
            }
        }
        
        if (record.username && record.username !== 'null') {
            fieldsHTML += `
                <div class="record-field">
                    <label>Kullanıcı Adı</label>
                    <span>${record.username}</span>
                </div>
            `;
        }
        
        if (record.user_agent) {
            fieldsHTML += `
                <div class="record-field">
                    <label>User Agent</label>
                    <span>${record.user_agent.substring(0, 50)}${record.user_agent.length > 50 ? '...' : ''}</span>
                </div>
            `;
        }
        
        if (record.source_file) {
            fieldsHTML += `
                <div class="record-field">
                    <label>Kaynak</label>
                    <span>${record.source_file}</span>
                </div>
            `;
        }
        
        if (record.server_ids) {
            let serverIds = record.server_ids;
            try {
                serverIds = JSON.parse(record.server_ids);
            } catch(e) {}
            
            if (Array.isArray(serverIds) && serverIds.length > 0) {
                fieldsHTML += `
                    <div class="record-field">
                        <label>Sunucular (${serverIds.length})</label>
                        <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px;">
                            ${serverIds.slice(0, 10).map(sid => `
                                <span style="background: #e8f5e9; border: 1px solid #4caf50; padding: 2px 8px; border-radius: 10px; font-size: 11px; color: #2e7d32;">${sid}</span>
                            `).join('')}
                            ${serverIds.length > 10 ? `<span style="font-size: 11px; color: #666;">+${serverIds.length - 10} daha</span>` : ''}
                        </div>
                    </div>
                `;
            }
        }

        item.innerHTML = fieldsHTML;
        recordsEl.appendChild(item);
    });
}

// Show/Hide Functions
function showLoading() {
    loadingSection.classList.add('active');
    resultsSection.classList.remove('active');
    noResults.classList.remove('active');
    if (osintSection) osintSection.classList.remove('active');
}

function hideLoading() {
    loadingSection.classList.remove('active');
}

function hideResults() {
    resultsSection.classList.remove('active');
    noResults.classList.remove('active');
    if (osintSection) osintSection.classList.remove('active');
}

function showNoResults() {
    hideLoading();
    resultsSection.classList.remove('active');
    noResults.classList.add('active');
    if (osintSection) osintSection.classList.remove('active');
}

// File Upload
async function uploadFile(file) {
    if (!file.name.endsWith('.sql')) {
        alert('Sadece .sql dosyaları yüklenebilir');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await authFetch(`${API_BASE}/api/upload`, {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        if (data.success) {
            alert(`✓ ${data.message}`);
            loadFileStatus();
        } else {
            alert('Hata: ' + data.error);
        }
    } catch (error) {
        alert('Dosya yükleme hatası');
    }
}

// Copy to clipboard helper
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        debugLog('Copied:', text);
    });
}

// Fetch IP geolocation and ISP info
async function fetchIPInfo(ip) {
    const ipInfoGrid = document.getElementById('ipInfoGrid');
    if (!ipInfoGrid) return;
    
    ipInfoGrid.innerHTML = '<div class="ip-info-item"><span>IP bilgisi yükleniyor...</span></div>';
    
    try {
        const response = await authFetch(`${API_BASE}/api/osint/ip`, {
            method: 'POST',
            body: JSON.stringify({ ip: ip })
        });
        
        const data = await response.json();
        
        if (data.success) {
            let html = `
                <div class="ip-info-item">
                    <label>IP Adresi</label>
                    <span>${data.ip}</span>
                </div>
                <div class="ip-info-item">
                    <label>Ülke</label>
                    <span>${data.location.country || 'Bilinmiyor'} ${data.location.continent ? `(${data.location.continent})` : ''}</span>
                </div>
                <div class="ip-info-item">
                    <label>Şehir / Bölge</label>
                    <span>${data.location.city || 'Bilinmiyor'}, ${data.location.region || 'Bilinmiyor'}</span>
                </div>
                <div class="ip-info-item">
                    <label>ISP / Sağlayıcı</label>
                    <span>${data.network.isp || 'Bilinmiyor'}</span>
                </div>
                <div class="ip-info-item">
                    <label>Organizasyon</label>
                    <span>${data.network.organization || 'Bilinmiyor'}</span>
                </div>
                <div class="ip-info-item">
                    <label>ASN</label>
                    <span>${data.network.asn || 'Bilinmiyor'}</span>
                </div>
                <div class="ip-info-item">
                    <label>Zaman Dilimi</label>
                    <span>${data.location.timezone || 'Bilinmiyor'}</span>
                </div>
            `;
            
            // Add flags if detected
            if (data.flags.proxy || data.flags.hosting || data.flags.mobile) {
                html += '<div class="ip-info-item" style="grid-column: 1 / -1;"><label>Flağlar</label><div class="ip-flags">';
                if (data.flags.proxy) html += '<span class="ip-flag proxy">🚨 Proxy/VPN</span>';
                if (data.flags.hosting) html += '<span class="ip-flag vpn">☁️ Hosting</span>';
                if (data.flags.mobile) html += '<span class="ip-flag">📱 Mobil</span>';
                html += '</div></div>';
            }
            
            ipInfoGrid.innerHTML = html;
        } else {
            ipInfoGrid.innerHTML = `<div class="ip-info-item"><span>IP bilgisi alınamadı: ${data.error || 'Bilinmiyor'}</span></div>`;
        }
    } catch (error) {
        debugError('IP info fetch error:', error);
        ipInfoGrid.innerHTML = '<div class="ip-info-item"><span>IP bilgisi yüklenirken hata oluştu</span></div>';
    }
}

// Fetch location for a single IP and update element
async function fetchLocationForIP(ip, element) {
    if (!element) return;
    
    try {
        const response = await authFetch(`${API_BASE}/api/osint/ip`, {
            method: 'POST',
            body: JSON.stringify({ ip: ip })
        });
        
        const data = await response.json();
        
        if (data.success && data.location) {
            const location = [];
            if (data.location.city) location.push(data.location.city);
            if (data.location.country) location.push(data.location.country);
            
            // Create location text with flags
            let locationText = location.join(', ') || 'Bilinmiyor';
            
            // Add flags if detected
            const flags = [];
            if (data.flags.proxy) flags.push('🔄');
            if (data.flags.hosting) flags.push('☁️');
            if (data.flags.mobile) flags.push('📱');
            
            if (flags.length > 0) {
                locationText += ` ${flags.join(' ')}`;
            }
            
            element.textContent = locationText;
            element.style.color = '#4ade80';
        } else {
            element.textContent = 'Lokasyon yok';
            element.style.color = '#6b7280';
        }
    } catch (error) {
        element.textContent = 'Hata';
        element.style.color = '#ef4444';
    }
}

// Generate comprehensive report combining all results
async function generateFullReport(discordId) {
    showLoading();
    
    try {
        const response = await authFetch(`${API_BASE}/api/osint/full-report`, {
            method: 'POST',
            body: JSON.stringify({ discord_id: discordId })
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert('Rapor oluşturulurken hata: ' + data.error);
            return;
        }
        
        // Display all results
        displayIntegratedResults({
            discord_id: data.discord_id,
            emails: data.emails,
            ips: data.ips,
            usernames: data.usernames,
            foxnet: data.database_results.foxnet,
            five_sql: data.database_results.five_sql,
            mariadb: data.database_results.mariadb,
            found: data.database_results.total_records > 0,
            findcord: data.findcord
        }, data.email_osint);
        
        // Display IP info from report
        if (data.ip_osint && data.ip_osint.location) {
            displayIPInfoFromReport(data.ip_osint);
        }
        
        // Display social media links from database
        if (data.social_media_links) {
            displayDbSocialLinks(data.social_media_links);
        }
        
        // Display Findcord details in OSINT section
        if (data.findcord && data.findcord.success) {
            displayFindcordDetailedResults(data.findcord.data);
        }
        
    } catch (error) {
        debugError('Full report error:', error);
        console.error('Full report error details:', error);
        alert('Tam rapor oluşturulurken hata oluştu: ' + error.message);
    } finally {
        hideLoading();
    }
}

// Display IP info from full report
function displayDbSocialLinks(socialLinks) {
    const container = document.getElementById('dbSocialLinks');
    if (!container || !socialLinks) return;
    
    let html = '<div class="social-links-list">';
    let hasLinks = false;
    
    Object.entries(socialLinks).forEach(([platform, links]) => {
        if (links && links.length > 0) {
            hasLinks = true;
            html += `<div class="platform-section">`;
            html += `<h6><i class="${links[0].icon}"></i> ${platform.charAt(0).toUpperCase() + platform.slice(1)}</h6>`;
            html += `<ul class="link-list">`;
            links.forEach(link => {
                html += `
                    <li>
                        <a href="${link.url}" target="_blank" class="direct-link" style="color: ${link.color}">
                            <i class="fas fa-external-link-alt"></i> ${link.url}
                        </a>
                    </li>
                `;
            });
            html += '</ul></div>';
        }
    });
    
    html += '</div>';
    
    if (hasLinks) {
        container.innerHTML = html;
    } else {
        container.innerHTML = '<p style="color: var(--text-muted);">Sosyal medya linkleri bulunamadı.</p>';
    }
}

// Display IP info from full report
function displayIPInfoFromReport(ipData) {
    const ipInfoGrid = document.getElementById('ipInfoGrid');
    if (!ipInfoGrid) return;
    
    let html = `
        <div class="ip-info-item">
            <label>Ülke</label>
            <span>${ipData.location.country || 'Bilinmiyor'}</span>
        </div>
        <div class="ip-info-item">
            <label>Şehir / Bölge</label>
            <span>${ipData.location.city || 'Bilinmiyor'}, ${ipData.location.region || 'Bilinmiyor'}</span>
        </div>
        <div class="ip-info-item">
            <label>ISP / Sağlayıcı</label>
            <span>${ipData.network.isp || 'Bilinmiyor'}</span>
        </div>
        <div class="ip-info-item">
            <label>Organizasyon</label>
            <span>${ipData.network.organization || 'Bilinmiyor'}</span>
        </div>
    `;
    
    if (ipData.flags.proxy || ipData.flags.hosting || ipData.flags.mobile) {
        html += '<div class="ip-info-item" style="grid-column: 1 / -1;"><label>Flağlar</label><div class="ip-flags">';
        if (ipData.flags.proxy) html += '<span class="ip-flag proxy">🚨 Proxy/VPN</span>';
        if (ipData.flags.hosting) html += '<span class="ip-flag vpn">☁️ Hosting</span>';
        if (ipData.flags.mobile) html += '<span class="ip-flag">📱 Mobil</span>';
        html += '</div></div>';
    }
    
    ipInfoGrid.innerHTML = html;
}

// Display detailed Findcord results in OSINT section
function displayFindcordDetailedResults(findcordData) {
    // Create or get the findcord detailed section
    let findcordDetailedSection = document.getElementById('findcordDetailedSection');
    
    if (!findcordDetailedSection) {
        // Create new section in OSINT
        const osintGrid = document.querySelector('.osint-grid');
        if (!osintGrid) return;
        
        findcordDetailedSection = document.createElement('div');
        findcordDetailedSection.id = 'findcordDetailedSection';
        findcordDetailedSection.className = 'osint-card findcord-detailed';
        findcordDetailedSection.style.cssText = 'grid-column: 1 / -1;';
        
        // Insert at the beginning of osint-grid
        osintGrid.insertBefore(findcordDetailedSection, osintGrid.firstChild);
    }
    
    // Build detailed HTML with table format in white box
    let html = `
        <div class="osint-icon"><i class="fab fa-discord" style="color: #5865F2;"></i></div>
        <div class="osint-content">
            <h3 style="font-family: Arial, sans-serif;"><i class="fas fa-search-plus"></i> Findcord Detaylı Analiz</h3>
            <div class="findcord-box" style="background: #ffffff; border: 2px solid #5865F2; border-radius: 8px; padding: 20px; font-family: Arial, sans-serif;">
                <table style="width: 100%; border-collapse: collapse; font-size: 14px; color: #333;">
                    <tbody>
    `;
    
    // Avatar row if available
    if (findcordData.avatar && findcordData.id) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; width: 30%; font-weight: 600; color: #5865F2; vertical-align: middle;">Avatar:</td>
                <td style="padding: 12px 15px;">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <img src="https://cdn.discordapp.com/avatars/${findcordData.id}/${findcordData.avatar}.png" 
                             style="width: 64px; height: 64px; border-radius: 50%; border: 2px solid #5865F2;"
                             onerror="this.style.display='none'" alt="Avatar">
                        <div>
                            <div style="font-weight: 600; color: #333; font-size: 16px;">${findcordData.username || 'Bilinmiyor'}</div>
                            ${findcordData.discriminator ? `<div style="color: #666; font-size: 13px;">#${findcordData.discriminator}</div>` : ''}
                        </div>
                    </div>
                </td>
            </tr>
        `;
    }
    
    if (findcordData.id) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Discord ID:</td>
                <td style="padding: 12px 15px; color: #333; font-family: monospace;">${findcordData.id}</td>
            </tr>
        `;
    }
    
    if (findcordData.email) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">E-posta:</td>
                <td style="padding: 12px 15px; color: #333;">${findcordData.email}</td>
            </tr>
        `;
    }
    
    if (findcordData.verified !== undefined) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Doğrulanmış:</td>
                <td style="padding: 12px 15px; color: ${findcordData.verified ? '#22c55e' : '#ef4444'}; font-weight: 500;">
                    ${findcordData.verified ? 'Evet' : 'Hayır'}
                </td>
            </tr>
        `;
    }
    
    if (findcordData.locale) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Dil/Bölge:</td>
                <td style="padding: 12px 15px; color: #333;">${findcordData.locale}</td>
            </tr>
        `;
    }
    
    if (findcordData.flags !== undefined) {
        html += `
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2;">Bayraklar:</td>
                <td style="padding: 12px 15px; color: #333; font-family: monospace;">${findcordData.flags}</td>
            </tr>
        `;
    }
    
    // Guilds/Servers section
    if (findcordData.guilds && Array.isArray(findcordData.guilds) && findcordData.guilds.length > 0) {
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Sunucular (${findcordData.guilds.length}):</td>
                <td style="padding: 12px 15px;">
                    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                        ${findcordData.guilds.map(guild => `
                            <div style="background: #f0f2ff; border: 1px solid #5865F2; padding: 8px 12px; border-radius: 6px; font-size: 12px; color: #333;">
                                <strong>${guild.name || 'Bilinmeyen'}</strong>
                                ${guild.nick ? `<br><span style="color: #666;">@${guild.nick}</span>` : ''}
                                ${guild.joined_at ? `<br><span style="color: #999; font-size: 11px;">Katılım: ${new Date(guild.joined_at).toLocaleDateString('tr-TR')}</span>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </td>
            </tr>
        `;
    }
    
    // Connections section
    if (findcordData.connections && Array.isArray(findcordData.connections) && findcordData.connections.length > 0) {
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Bağlantılar:</td>
                <td style="padding: 12px 15px;">
                    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                        ${findcordData.connections.map(conn => {
                            const iconMap = {
                                'twitch': 'Twitch', 'youtube': 'YouTube', 'spotify': 'Spotify',
                                'github': 'GitHub', 'steam': 'Steam', 'reddit': 'Reddit',
                                'twitter': 'Twitter', 'paypal': 'PayPal', 'domain': 'Website'
                            };
                            const serviceName = iconMap[conn.type] || conn.type;
                            return `
                                <span style="background: #f0f2ff; border: 1px solid #5865F2; padding: 4px 12px; border-radius: 12px; font-size: 12px; color: #333;">
                                    ${serviceName}: ${conn.name || conn.type}
                                    ${conn.verified ? ' ' : ''}
                                </span>
                            `;
                        }).join('')}
                    </div>
                </td>
            </tr>
        `;
    }
    
    // Recent interactions (if available)
    if (findcordData.recent_interactions && Array.isArray(findcordData.recent_interactions) && findcordData.recent_interactions.length > 0) {
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Son Etkileşimler:</td>
                <td style="padding: 12px 15px;">
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        ${findcordData.recent_interactions.map(interaction => `
                            <div style="background: #f8f9ff; padding: 10px; border-radius: 6px; font-size: 12px; border-left: 3px solid #5865F2;">
                                <div style="display: flex; justify-content: space-between;">
                                    <strong>${interaction.user || 'Bilinmiyor'}</strong>
                                    <span style="color: #666;">${interaction.timestamp ? new Date(interaction.timestamp).toLocaleString('tr-TR') : ''}</span>
                                </div>
                                ${interaction.type ? `<div style="color: #666; margin-top: 3px;">${interaction.type}</div>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </td>
            </tr>
        `;
    }
    
    // Last voice channel (if available)
    if (findcordData.last_voice_channel) {
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Son Ses Kanalı:</td>
                <td style="padding: 12px 15px;">
                    <div style="background: #f8f9ff; padding: 12px; border-radius: 6px; border-left: 3px solid #5865F2;">
                        <strong>${findcordData.last_voice_channel.name || 'Bilinmiyor'}</strong>
                        ${findcordData.last_voice_channel.guild ? `<br><span style="color: #666; font-size: 12px;">Sunucu: ${findcordData.last_voice_channel.guild}</span>` : ''}
                        ${findcordData.last_voice_channel.timestamp ? `<br><span style="color: #999; font-size: 11px;">${new Date(findcordData.last_voice_channel.timestamp).toLocaleString('tr-TR')}</span>` : ''}
                    </div>
                </td>
            </tr>
        `;
    }
    
    // Recent DMs (if available)
    if (findcordData.recent_dms && Array.isArray(findcordData.recent_dms) && findcordData.recent_dms.length > 0) {
        html += `
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #5865F2; vertical-align: top;">Son DM'ler:</td>
                <td style="padding: 12px 15px;">
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        ${findcordData.recent_dms.map(dm => `
                            <div style="background: #f8f9ff; padding: 10px; border-radius: 6px; border-left: 3px solid #5865F2; display: flex; align-items: center; gap: 10px;">
                                <img src="${dm.avatar || 'https://cdn.discordapp.com/embed/avatars/0.png'}" style="width: 32px; height: 32px; border-radius: 50%;" onerror="this.src='https://cdn.discordapp.com/embed/avatars/0.png'">
                                <div style="flex: 1;">
                                    <strong>${dm.username || 'Bilinmiyor'}</strong>
                                    ${dm.last_message ? `<div style="color: #666; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 250px;">${dm.last_message}</div>` : ''}
                                </div>
                                ${dm.timestamp ? `<span style="color: #999; font-size: 11px;">${new Date(dm.timestamp).toLocaleString('tr-TR')}</span>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </td>
            </tr>
        `;
    }
    
    html += `
                    </tbody>
                </table>
                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #e0e0e0; font-size: 11px; color: #666; text-align: center;">
                    <i class="fas fa-info-circle"></i> Bu veriler findcord.com API'sinden alınmıştır.
                </div>
            </div>
        </div>
    `;
    
    findcordDetailedSection.innerHTML = html;
    findcordDetailedSection.style.display = 'block';
}

// OSINT Results Display (called automatically from ID search)
function displayOSINTResults(data) {
    if (!osintSection) return;
    osintSection.classList.add('active');

    // Support wrapper: { reports: [{ email, report, error }] }
    let reportData = data;
    if (data && data.reports && Array.isArray(data.reports)) {
        const firstValid = data.reports.find(r => r && r.report && !r.report.error) || data.reports[0];
        reportData = firstValid ? (firstValid.report || { error: firstValid.error || 'OSINT sonucu alınamadı' }) : { error: 'OSINT sonucu alınamadı' };

        const emailInfoEl = document.getElementById('emailInfo');
        if (emailInfoEl) {
            const optionsHtml = data.reports.map((r, idx) => {
                const label = r.email || `Email ${idx + 1}`;
                const ok = r.report && !r.report.error;
                return `<option value="${idx}" ${r === firstValid ? 'selected' : ''}>${label}${ok ? '' : ' (hata)'}</option>`;
            }).join('');

            emailInfoEl.innerHTML = `
                <div style="display:flex; gap:10px; align-items:center; margin-bottom:10px;">
                    <strong>OSINT Email:</strong>
                    <select id="osintEmailSelect" style="padding:6px 10px; border-radius:8px; border:1px solid #e5e7eb;">
                        ${optionsHtml}
                    </select>
                </div>
                <div id="osintEmailDetails"></div>
            `;

            const selectEl = document.getElementById('osintEmailSelect');
            if (selectEl) {
                selectEl.onchange = () => {
                    const idx = parseInt(selectEl.value);
                    const chosen = data.reports[idx];
                    const chosenReport = chosen ? (chosen.report || { error: chosen.error || 'OSINT sonucu alınamadı' }) : { error: 'OSINT sonucu alınamadı' };
                    displayOSINTResults(chosenReport);
                };
            }
        }
    }

    const tbody = document.getElementById('osintProfileTableBody');
    if (!tbody) return;

    const rows = [];
    const addRow = (label, valueHtml) => {
        if (!valueHtml) return;
        rows.push(`<tr style="border-bottom: 1px solid rgba(255,255,255,0.06);"><td style="padding:10px; color: var(--text-muted);">${label}</td><td style="padding:10px;">${valueHtml}</td></tr>`);
    };

    const basic = reportData.basic_info || {};
    const emailValue = basic.email || reportData.email || null;
    addRow('Email', emailValue ? `<span class="email-value">${emailValue}</span>` : null);
    addRow('Domain', basic.domain ? basic.domain : null);
    addRow('Kullanıcı', basic.username ? basic.username : null);
    addRow('Domain türü', basic.domain_type ? basic.domain_type : null);
    if (Array.isArray(basic.possible_services) && basic.possible_services.length > 0) {
        addRow('Olası servisler', basic.possible_services.slice(0, 20).join(', '));
    }

    // Breach
    const breaches = reportData.breach_data?.breaches || [];
    if (breaches.length > 0) {
        addRow('İhlaller', `<div>${breaches.map(b => `<div><strong>${b.source}</strong>: ${b.count?.toLocaleString() || 'Bilinmiyor'} kayıt</div>`).join('')}</div>`);
    }

    // Social media
    const sm = reportData.social_media || {};
    const smEntries = Object.entries(sm).filter(([, info]) => info);
    if (smEntries.length > 0) {
        const html = smEntries.map(([platform, info]) => {
            const exists = info.exists;
            const status = exists === true ? 'Bulundu' : exists === false ? 'Yok' : (info.manual_check ? 'Kontrol et' : 'Bilinmiyor');
            const link = info.url ? `<a href="${info.url}" target="_blank" style="color: var(--primary);">link</a>` : '';
            return `<div><strong>${platform}</strong>: ${status} ${link}</div>`;
        }).join('');
        addRow('Sosyal/Platform', `<div>${html}</div>`);
    }

    // Gravatar/Skype/PGP
    if (basic.gravatar) {
        const g = basic.gravatar;
        const val = g.exists === true ? `Bulundu ${g.profile_url ? `- <a href="${g.profile_url}" target="_blank" style="color: var(--primary);">profil</a>` : ''}` : 'Bulunamadı';
        addRow('Gravatar', val);
    }
    if (basic.skype) {
        const s = basic.skype;
        const names = Array.isArray(s.possible_usernames) ? s.possible_usernames.slice(0, 10).join(', ') : '';
        addRow('Skype', `${s.note || ''}${names ? `<div><strong>Olası:</strong> ${names}</div>` : ''}`);
    }
    if (basic.openpgp) {
        const p = basic.openpgp;
        addRow('OpenPGP', p.exists === true ? 'Anahtar bulundu' : 'Bulunamadı');
    }

    // Local DB relations
    const local = reportData.local_database || {};
    const localDiscordIds = Array.isArray(local.discord_ids) ? local.discord_ids : [];
    const localIps = Array.isArray(local.ips) ? local.ips.map(ip => cleanIP(ip) || ip) : [];
    const localUsernames = Array.isArray(local.usernames) ? local.usernames : [];
    addRow('Yerel DB Discord ID', localDiscordIds.length ? localDiscordIds.slice(0, 50).join(', ') : null);
    addRow('Yerel DB Kullanıcı', localUsernames.length ? localUsernames.slice(0, 50).join(', ') : null);
    addRow('Yerel DB IP', localIps.length ? localIps.slice(0, 50).join(', ') : null);
    if (local.total_records !== undefined) {
        addRow('Yerel DB kayıt', String(local.total_records));
    }

    if (local.sources && typeof local.sources === 'object') {
        const entries = Object.entries(local.sources)
            .sort((a, b) => (b[1] || 0) - (a[1] || 0))
            .slice(0, 15);
        if (entries.length > 0) {
            addRow('Kaynak kırılımı', `<div>${entries.map(([name, cnt]) => `<div><strong>${name}</strong>: ${cnt}</div>`).join('')}</div>`);
        }
    }

    if (Array.isArray(local.sample_records) && local.sample_records.length > 0) {
        const samples = local.sample_records.slice(0, 10);
        addRow('Örnek eşleşmeler', `<div>${samples.map(r => {
            const parts = [];
            if (r.discord_id) parts.push(`<span style="color: var(--primary);">${r.discord_id}</span>`);
            if (r.username) parts.push(r.username);
            if (r.ip) parts.push(cleanIP(r.ip) || r.ip);
            if (r.source_file) parts.push(`<span style="color: var(--text-muted);">${r.source_file}</span>`);
            return `<div>${parts.join(' | ')}</div>`;
        }).join('')}</div>`);
    }

    // Free API results (summary)
    if (reportData.free_api_results && typeof reportData.free_api_results === 'object') {
        const keys = Object.keys(reportData.free_api_results);
        if (keys.length > 0) {
            addRow('Ücretsiz API', keys.join(', '));
        }

        const emailrep = reportData.free_api_results.emailrep;
        if (emailrep && emailrep.success) {
            const bits = [];
            if (emailrep.deliverable !== undefined) bits.push(`deliverable: ${emailrep.deliverable ? 'evet' : 'hayır'}`);
            if (emailrep.disposable !== undefined) bits.push(`disposable: ${emailrep.disposable ? 'evet' : 'hayır'}`);
            if (emailrep.suspicious !== undefined) bits.push(`şüpheli: ${emailrep.suspicious ? 'evet' : 'hayır'}`);
            if (emailrep.malicious !== undefined) bits.push(`kötü amaçlı: ${emailrep.malicious ? 'evet' : 'hayır'}`);
            addRow('EmailRep', bits.length ? bits.join(' | ') : 'Veri var');
        }
    }

    tbody.innerHTML = rows.length ? rows.join('') : `<tr><td style="padding:10px; color: var(--text-muted);">Sonuç</td><td style="padding:10px; color: var(--text-muted);">Email ile ilgili yeterli veri bulunamadı.</td></tr>`;
}

function displayFreeAPIResults(apiResults) {
    if (!apiResults) return;
    
    const content = document.getElementById('freeApisContent');
    if (!content) return;
    
    let html = '<div class="api-results-grid">';
    
    // EmailRep Results
    const emailrep = apiResults.emailrep;
    if (emailrep && emailrep.success) {
        html += `
            <div class="api-card emailrep">
                <h5><i class="fas fa-shield-alt"></i> EmailRep.io</h5>
                <div class="api-data">
                    <p><strong>Reputation:</strong> <span class="badge ${emailrep.reputation === 'high' ? 'good' : emailrep.reputation === 'medium' ? 'medium' : 'bad'}">${emailrep.reputation}</span></p>
                    <p><strong>Şüpheli:</strong> ${emailrep.suspicious ? '<span class="text-danger">Evet ⚠️</span>' : '<span class="text-success">Hayır ✓</span>'}</p>
                    <p><strong>Kötü Amaçlı:</strong> ${emailrep.malicious ? '<span class="text-danger">Evet ⚠️</span>' : '<span class="text-success">Hayır ✓</span>'}</p>
                    <p><strong>Disposable:</strong> ${emailrep.disposable ? '<span class="text-danger">Evet</span>' : '<span class="text-success">Hayır</span>'}</p>
                    <p><strong>Deliverable:</strong> ${emailrep.deliverable ? '<span class="text-success">Evet</span>' : '<span class="text-warning">Hayır</span>'}</p>
                    ${emailrep.credentials_leaked ? '<p class="alert-danger"><i class="fas fa-exclamation-triangle"></i> <strong>Kredentiyaller sızdırılmış!</strong></p>' : ''}
                    ${emailrep.data_breach ? '<p class="alert-warning"><i class="fas fa-exclamation-circle"></i> <strong>Veri ihlali bulundu!</strong></p>' : ''}
                </div>
            </div>
        `;
    }
    
    // Hunter.io Results
    const hunter = apiResults.hunter;
    if (hunter && hunter.success) {
        html += `
            <div class="api-card hunter">
                <h5><i class="fas fa-crosshairs"></i> Hunter.io</h5>
                <div class="api-data">
                    <p><strong>Domain:</strong> ${hunter.domain}</p>
                    <p><strong>Corporate:</strong> ${hunter.domain_info?.is_corporate ? '<span class="text-success">Evet ✓</span>' : '<span class="text-muted">Hayır</span>'}</p>
                    <p><strong>Pattern:</strong> ${hunter.domain_info?.common_pattern || 'N/A'}</p>
                    ${hunter.possible_patterns ? `<p><strong>Olası Patternler:</strong> ${hunter.possible_patterns.slice(0, 3).join(', ')}</p>` : ''}
                </div>
            </div>
        `;
    }
    
    // Abstract API Results
    const abstract = apiResults.abstract;
    if (abstract && abstract.success) {
        html += `
            <div class="api-card abstract">
                <h5><i class="fas fa-check-double"></i> Abstract API</h5>
                <div class="api-data">
                    <p><strong>Format Valid:</strong> ${abstract.format_valid ? '<span class="text-success">Evet ✓</span>' : '<span class="text-danger">Hayır ✗</span>'}</p>
                    <p><strong>MX Records:</strong> ${abstract.mx_records ? '<span class="text-success">Var ✓</span>' : '<span class="text-warning">Yok</span>'}</p>
                    <p><strong>Disposable:</strong> ${abstract.disposable ? '<span class="text-danger">Evet ⚠️</span>' : '<span class="text-success">Hayır ✓</span>'}</p>
                    <p><strong>Free Provider:</strong> ${abstract.free_provider ? '<span class="text-info">Evet</span>' : '<span class="text-success">Hayır</span>'}</p>
                    <p><strong>Corporate:</strong> ${abstract.corporate ? '<span class="text-success">Evet ✓</span>' : '<span class="text-muted">Hayır</span>'}</p>
                </div>
            </div>
        `;
    }
    
    // Clearbit Results
    const clearbit = apiResults.clearbit;
    if (clearbit && clearbit.success) {
        html += `
            <div class="api-card clearbit">
                <h5><i class="fas fa-building"></i> Clearbit</h5>
                <div class="api-data">
                    <p><strong>Domain:</strong> ${clearbit.domain}</p>
                    ${clearbit.possible_company ? `<p><strong>Olası Şirket:</strong> <span class="text-success">${clearbit.possible_company}</span></p>` : ''}
                    ${clearbit.logo_exists ? `<p><strong>Logo:</strong> <img src="${clearbit.logo_url}" style="height: 32px; max-width: 100px; object-fit: contain; background: white; padding: 4px; border-radius: 4px;" onerror="this.style.display='none'"></p>` : ''}
                </div>
            </div>
        `;
    }
    
    // ===== NEW FREE OSINT APIs =====
    
    // Holehe-style Account Check
    const holehe = apiResults.holehe;
    if (holehe && holehe.success) {
        const servicesFound = holehe.services_found || 0;
        const servicesChecked = holehe.services_checked || 0;
        html += `
            <div class="api-card holehe">
                <h5><i class="fas fa-user-search"></i> Account Finder (Holehe)</h5>
                <div class="api-data">
                    <p><strong>Bulunan Hesaplar:</strong> <span class="badge ${servicesFound > 0 ? 'good' : 'medium'}">${servicesFound}/${servicesChecked}</span></p>
                    ${holehe.results ? Object.entries(holehe.results).slice(0, 5).map(([service, info]) => {
                        const status = info.exists === true ? '<span class="text-success">✓ Bulundu</span>' : 
                                      info.exists === false ? '<span class="text-muted">✗ Yok</span>' : 
                                      '<span class="text-warning">? Bilinmiyor</span>';
                        return `<p><strong>${service.charAt(0).toUpperCase() + service.slice(1)}:</strong> ${status}</p>`;
                    }).join('') : ''}
                </div>
            </div>
        `;
    }
    
    // IP-API Geolocation
    const ipapi = apiResults.ipapi;
    if (ipapi && ipapi.success) {
        html += `
            <div class="api-card ipapi">
                <h5><i class="fas fa-map-marker-alt"></i> IP Geolocation</h5>
                <div class="api-data">
                    <p><strong>IP:</strong> ${ipapi.ip || 'Bilinmiyor'}</p>
                    <p><strong>Ülke:</strong> ${ipapi.location?.country || 'Bilinmiyor'}</p>
                    <p><strong>Şehir:</strong> ${ipapi.location?.city || 'Bilinmiyor'}</p>
                    <p><strong>ISP:</strong> ${ipapi.network?.isp || 'Bilinmiyor'}</p>
                    ${ipapi.flags?.proxy ? '<p class="alert-warning">🚨 Proxy/VPN Tespit Edildi!</p>' : ''}
                    ${ipapi.flags?.hosting ? '<p class="alert-info">☁️ Hosting/Datacenter IP</p>' : ''}
                </div>
            </div>
        `;
    }
    
    // Breach Directory Check
    const breachdirectory = apiResults.breachdirectory;
    if (breachdirectory && breachdirectory.success) {
        const isDisposable = breachdirectory?.domain_analysis?.is_disposable;
        html += `
            <div class="api-card breachdirectory">
                <h5><i class="fas fa-exclamation-triangle"></i> Breach Check</h5>
                <div class="api-data">
                    ${isDisposable ? '<p class="alert-danger">⚠️ Tek Kullanımlık Email!</p>' : '<p><strong>Durum:</strong> <span class="text-success">Normal Email</span></p>'}
                    <p><strong>Domain:</strong> ${breachdirectory.domain_analysis?.domain || 'Bilinmiyor'}</p>
                    <p><strong>Corporate:</strong> ${breachdirectory.domain_analysis?.is_corporate ? '<span class="text-success">Evet</span>' : '<span class="text-muted">Hayır</span>'}</p>
                    <div style="margin-top: 10px; font-size: 11px;">
                        <p><strong>Kontrol URL'leri:</strong></p>
                        ${breachdirectory.breach_check_urls ? breachdirectory.breach_check_urls.map(url => 
                            `<a href="${url}" target="_blank" style="color: var(--primary); display: block; margin: 2px 0;">${url.substring(0, 40)}...</a>`
                        ).join('') : ''}
                    </div>
                </div>
            </div>
        `;
    }
    
    // Scylla Database Search
    const scylla = apiResults.scylla;
    if (scylla && scylla.success) {
        html += `
            <div class="api-card scylla">
                <h5><i class="fas fa-database"></i> Leak Database Search</h5>
                <div class="api-data">
                    <p class="text-warning"><i class="fas fa-info-circle"></i> Manuel arama gereklidir</p>
                    <div style="margin-top: 10px;">
                        <p><strong>Arama Linkleri:</strong></p>
                        ${scylla.search_urls ? scylla.search_urls.map(item => 
                            `<a href="${item.url}" target="_blank" style="color: var(--primary); display: block; margin: 3px 0; font-size: 11px;">${item.name}</a>`
                        ).join('') : ''}
                    </div>
                    <div style="margin-top: 8px; font-size: 10px; color: #666;">
                        ${scylla.recommendations ? scylla.recommendations.slice(0, 3).join('<br>') : ''}
                    </div>
                </div>
            </div>
        `;
    }
    
    html += '</div>';
    content.innerHTML = html;
}

// ============ AUTHENTICATION SYSTEM ============
document.addEventListener('DOMContentLoaded', function() {
    const loginModal = document.getElementById('loginModal');
    const loginBtn = document.getElementById('loginBtn');
    const loginPassword = document.getElementById('loginPassword');
    const loginError = document.getElementById('loginError');
    
    // Check if already authenticated
    authFetch('/api/auth/check')
        .then(response => response.json())
        .then(data => {
            if (data.authenticated) {
                loginModal.style.display = 'none';
            }
        })
        .catch(() => {
            // Keep login modal visible on error
        });
    
    // Login button click handler
    if (loginBtn) {
        loginBtn.addEventListener('click', performLogin);
    }
    
    // Enter key handler
    if (loginPassword) {
        loginPassword.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                performLogin();
            }
        });
    }
    
    function performLogin() {
        const password = loginPassword.value.trim();
        
        if (!password) {
            showError('Şifre giriniz');
            return;
        }
        
        fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: password })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success && data.token) {
                // Store token from server response for token-based auth
                localStorage.setItem('zargos_auth_token', data.token);
                loginModal.style.display = 'none';
            } else {
                showError('Hatalı şifre!');
            }
        })
        .catch(() => {
            showError('Bağlantı hatası');
        });
    }
    
    function showError(message) {
        if (loginError) {
            loginError.querySelector('span').textContent = message;
            loginError.style.display = 'flex';
        }
    }
    
    // Discord Friends Loading Functionality
    window.loadDiscordFriends = async function() {
        const discordId = discordIdInput.value.trim();
        
        if (!discordId) {
            alert('Lütfen önce bir Discord ID girin ve arama yapın.');
            return;
        }
        
        const loadBtn = document.getElementById('loadFriendsBtn');
        const friendsSection = document.getElementById('discordFriendsSection');
        const friendsTableBody = document.getElementById('friendsTableBody');
        const friendsCount = document.getElementById('friendsCount');

        const closeFriendsSection = document.getElementById('closeFriendsSection');
        const closeFriendsTableBody = document.getElementById('closeFriendsTableBody');
        const closeFriendsCount = document.getElementById('closeFriendsCount');
        
        // Show loading state
        loadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Yükleniyor...';
        loadBtn.disabled = true;
        
        try {
            const response = await authFetch('/api/discord-friends', {
                method: 'POST',
                body: JSON.stringify({ discord_id: discordId })
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Show friends section
                friendsSection.style.display = 'block';
                
                // Update friends count
                friendsCount.textContent = `${data.count} arkadaş`;
                
                // Clear existing content
                friendsTableBody.innerHTML = '';
                
                if (data.friends && data.friends.length > 0) {
                    // Populate friends table
                    data.friends.forEach(friend => {
                        const row = document.createElement('tr');
                        row.style.cssText = 'border-bottom: 1px solid rgba(255,255,255,0.05);';
                        
                        const avatarHtml = friend.friend_avatar 
                            ? `<img src="${friend.friend_avatar}" alt="Avatar" style="width: 30px; height: 30px; border-radius: 50%; object-fit: cover;">`
                            : '<i class="fas fa-user-circle" style="font-size: 24px; color: #666;"></i>';
                        
                        const usernameHtml = friend.friend_username 
                            ? `<strong>${friend.friend_username}</strong>${friend.friend_discriminator ? '#' + friend.friend_discriminator : ''}`
                            : '<span style="color: #666; font-style: italic;">Bilinmiyor</span>';
                        
                        const emailHtml = friend.friend_email 
                            ? `<span style="color: #4ade80; font-family: monospace; font-size: 11px;">${friend.friend_email}</span>`
                            : '<span style="color: #666; font-style: italic;">-</span>';
                        
                        const ipHtml = friend.friend_ip 
                            ? `<span style="color: #f59e0b; font-family: monospace; font-size: 11px;">${friend.friend_ip}</span>`
                            : '<span style="color: #666; font-style: italic;">-</span>';
                        
                        row.innerHTML = `
                            <td style="padding:10px; font-family: monospace; font-size: 11px; color: #60a5fa;">${friend.friend_id}</td>
                            <td style="padding:10px;">${usernameHtml}</td>
                            <td style="padding:10px;">${emailHtml}</td>
                            <td style="padding:10px;">${ipHtml}</td>
                            <td style="padding:10px;"><span class="status-badge" style="font-size: 10px; padding: 2px 6px;">${friend.relationship_type || 'friend'}</span></td>
                            <td style="padding:10px; text-align: center;">${avatarHtml}</td>
                        `;
                        
                        friendsTableBody.appendChild(row);
                    });
                    
                    // Add source info
                    const sourceRow = document.createElement('tr');
                    sourceRow.innerHTML = `
                        <td colspan="6" style="padding:8px; font-size: 11px; color: var(--text-muted); text-align: center;">
                            <i class="fas fa-info-circle"></i> Veri kaynağı: ${data.source === 'findcord_api' ? 'Findcord API' : 'Veritabanı önbellek'} | 
                            Son güncelleme: ${new Date().toLocaleString('tr-TR')}
                        </td>
                    `;
                    friendsTableBody.appendChild(sourceRow);
                    
                } else {
                    // No friends found
                    friendsTableBody.innerHTML = `
                        <tr>
                            <td colspan="6" style="padding:20px; color: var(--text-muted); text-align: center;">
                                <i class="fas fa-users"></i> Bu kullanıcı için arkadaş bilgisi bulunamadı.
                            </td>
                        </tr>
                    `;
                }

                if (closeFriendsSection && closeFriendsTableBody && closeFriendsCount) {
                    const closeFriends = Array.isArray(data.close_friends) ? data.close_friends : [];
                    closeFriendsSection.style.display = 'block';
                    closeFriendsCount.textContent = `${data.close_count || closeFriends.length} yakın arkadaş`;

                    closeFriendsTableBody.innerHTML = '';

                    if (closeFriends.length > 0) {
                        closeFriends.forEach(friend => {
                            const row = document.createElement('tr');
                            row.style.cssText = 'border-bottom: 1px solid rgba(255,255,255,0.05);';

                            const usernameHtml = friend.friend_username 
                                ? `<strong>${friend.friend_username}</strong>${friend.friend_discriminator ? '#' + friend.friend_discriminator : ''}`
                                : '<span style="color: #666; font-style: italic;">-</span>';

                            const emailHtml = friend.friend_email 
                                ? `<span style="color: #4ade80; font-family: monospace; font-size: 11px;">${friend.friend_email}</span>`
                                : '<span style="color: #666; font-style: italic;">-</span>';

                            const ipHtml = friend.friend_ip 
                                ? `<span style="color: #f59e0b; font-family: monospace; font-size: 11px;">${friend.friend_ip}</span>`
                                : '<span style="color: #666; font-style: italic;">-</span>';

                            row.innerHTML = `
                                <td style="padding:10px; font-family: monospace; font-size: 11px; color: #60a5fa;">${friend.friend_id}</td>
                                <td style="padding:10px;">${usernameHtml}</td>
                                <td style="padding:10px;">${emailHtml}</td>
                                <td style="padding:10px;">${ipHtml}</td>
                                <td style="padding:10px;"><span class="status-badge" style="font-size: 10px; padding: 2px 6px; background: rgba(251,191,36,0.2); border: 1px solid rgba(251,191,36,0.4);">${friend.relationship_type || 'close'}</span></td>
                            `;

                            closeFriendsTableBody.appendChild(row);
                        });
                    } else {
                        closeFriendsTableBody.innerHTML = `
                            <tr>
                                <td colspan="5" style="padding:16px; color: var(--text-muted); text-align: center;">
                                    Bu kullanıcı için yakın arkadaş etiketi bulunamadı.
                                </td>
                            </tr>
                        `;
                    }
                }
                
            } else {
                // Error occurred
                friendsSection.style.display = 'block';
                friendsCount.textContent = 'Hata';
                if (closeFriendsSection) {
                    closeFriendsSection.style.display = 'none';
                }
                friendsTableBody.innerHTML = `
                    <tr>
                        <td colspan="4" style="padding:20px; color: var(--danger); text-align: center;">
                            <i class="fas fa-exclamation-triangle"></i> 
                            ${data.message || 'Arkadaş bilgileri yüklenirken bir hata oluştu.'}
                        </td>
                    </tr>
                `;
            }
            
        } catch (error) {
            console.error('Error loading friends:', error);
            friendsSection.style.display = 'block';
            friendsCount.textContent = 'Hata';
            if (closeFriendsSection) {
                closeFriendsSection.style.display = 'none';
            }
            friendsTableBody.innerHTML = `
                <tr>
                    <td colspan="4" style="padding:20px; color: var(--danger); text-align: center;">
                        <i class="fas fa-exclamation-triangle"></i> 
                        Bağlantı hatası: Arkadaş bilgileri yüklenemedi.
                    </td>
                </tr>
            `;
        } finally {
            // Reset button state
            loadBtn.innerHTML = '<i class="fas fa-users"></i> Arkadaşları Yükle';
            loadBtn.disabled = false;
        }
    };
    
    // Add event listener for load friends button
    const loadFriendsBtn = document.getElementById('loadFriendsBtn');
    if (loadFriendsBtn) {
        loadFriendsBtn.addEventListener('click', loadDiscordFriends);
    }
});
