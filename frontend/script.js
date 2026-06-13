document.addEventListener('DOMContentLoaded', () => {
    // Tab switching
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const tab = btn.dataset.tab;
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.add('hidden');
            });
            document.getElementById(tab + '-tab').classList.remove('hidden');
        });
    });

    // Voice analysis
    const voiceBtn = document.getElementById('voice-btn');
    const voiceLoading = document.getElementById('voice-loading');
    const transcriptDisplay = document.getElementById('transcript-display');

    if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
        const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
        const recognition = new SpeechRecognition();
        recognition.continuous = false;
        recognition.interimResults = false;
        recognition.lang = 'en-US';

        recognition.onstart = () => {
            voiceLoading.classList.remove('hidden');
            transcriptDisplay.classList.add('hidden');
            voiceBtn.textContent = '🎤 Listening...';
            voiceBtn.disabled = true;
        };

        recognition.onresult = async (event) => {
            const transcript = event.results[0][0].transcript;
            transcriptDisplay.textContent = `"${transcript}"`;
            transcriptDisplay.classList.remove('hidden');

            // Send to backend for analysis
            try {
                const res = await fetch('/api/analyze_text', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: transcript })
                });
                const data = await res.json();
                if (res.ok) {
                    updateUI(data);
                } else {
                    alert('Error analyzing text: ' + (data.detail || 'Unknown error'));
                }
            } catch (err) {
                alert('Failed to analyze text.');
                console.error(err);
            }
        };

        recognition.onend = () => {
            voiceLoading.classList.add('hidden');
            voiceBtn.textContent = '🎤 Start Voice Analysis';
            voiceBtn.disabled = false;
        };

        recognition.onerror = (event) => {
            voiceLoading.classList.add('hidden');
            voiceBtn.textContent = '🎤 Start Voice Analysis';
            voiceBtn.disabled = false;
            alert('Speech recognition error: ' + event.error);
        };

        voiceBtn.addEventListener('click', () => {
            recognition.start();
        });
    } else {
        voiceBtn.disabled = true;
        voiceBtn.textContent = 'Voice not supported';
    }
});

document.getElementById('analyze-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const url = document.getElementById('url-input').value;
    const loading = document.getElementById('loading');
    const resultsContainer = document.getElementById('results-container');
    const btn = document.getElementById('analyze-btn');
    
    // UI Reset
    resultsContainer.classList.add('hidden');
    loading.classList.remove('hidden');
    btn.disabled = true;
    
    try {
        const res = await fetch('/api/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        const data = await res.json();
        
        if (!res.ok) {
            alert('Error: ' + (data.detail || 'Failed to analyze URL'));
            return;
        }
        
        updateUI(data);
        
    } catch (err) {
        alert('Failed to connect to the server.');
        console.error(err);
    } finally {
        loading.classList.add('hidden');
        btn.disabled = false;
    }
});

function updateUI(data) {
    const resultsContainer = document.getElementById('results-container');
    const scoreCircle = document.getElementById('score-circle');
    const scoreText = document.getElementById('score-text');
    const riskStatus = document.getElementById('risk-status');
    const riskDesc = document.getElementById('risk-description');
    const factorsList = document.getElementById('factors-list');
    const analyzedContent = document.getElementById('analyzed-content');
    
    // Set ring and color
    const score = data.risk_score;
    // Cap at 100 for display geometry
    const displayScore = Math.min(score, 100);
    scoreCircle.setAttribute('stroke-dasharray', `${displayScore}, 100`);
    
    let color = '#22c55e'; // safe (green)
    let status = 'Safe';
    let desc = 'This content has a low probability of being a phishing attempt.';
    
    if (score >= 50 && score < 75) {
        color = '#f59e0b'; // warning (orange)
        status = 'Suspicious';
        desc = 'This content has some suspicious characteristics. Proceed with caution.';
    } else if (score >= 75) {
        color = '#ef4444'; // danger (red)
        status = 'High Risk';
        desc = 'This content exhibits strong indicators of a phishing attack. Do not proceed.';
    }
    
    scoreCircle.style.stroke = color;
    scoreText.textContent = `${Math.round(score)}%`;
    riskStatus.textContent = status;
    riskStatus.style.color = color;
    riskDesc.textContent = desc;
    
    // Set analyzed content
    analyzedContent.textContent = data.url || data.text;
    
    // Populate factors
    factorsList.innerHTML = '';
    data.risk_factors.forEach(factor => {
        const li = document.createElement('li');
        li.textContent = factor;
        li.className = data.is_phishing ? 'danger-factor' : 'safe-factor';
        factorsList.appendChild(li);
    });
    
    // Update hidden form inputs for PDF generation (only for URL)
    if (data.url) {
        document.getElementById('rep-url').value = data.url;
        document.getElementById('rep-phishing').value = data.is_phishing;
        document.getElementById('rep-score').value = data.risk_score;
        document.getElementById('rep-factors').value = JSON.stringify(data.risk_factors);
    }
    
    resultsContainer.classList.remove('hidden');
    
    // Refresh history after scan
    loadHistory();
}

async function loadHistory() {
    const historySection = document.getElementById('history-section');
    const historyBody = document.getElementById('history-body');
    const noHistoryMsg = document.getElementById('no-history-msg');
    const table = document.getElementById('history-table');
    
    if (!historySection) return;
    
    try {
        const res = await fetch('/api/history');
        if (!res.ok) throw new Error('Failed to fetch history');
        
        const data = await res.json();
        
        historySection.classList.remove('hidden');
        historyBody.innerHTML = '';
        
        if (data.length === 0) {
            table.classList.add('hidden');
            noHistoryMsg.classList.remove('hidden');
        } else {
            table.classList.remove('hidden');
            noHistoryMsg.classList.add('hidden');
            
            data.forEach(row => {
                const tr = document.createElement('tr');
                const badgeClass = row.Result === 'Phishing' ? 'badge-phishing' : 'badge-safe';
                
                tr.innerHTML = `
                    <td>${row.Timestamp}</td>
                    <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${row.URL}">${row.URL}</td>
                    <td><span class="${badgeClass}">${row.Result}</span></td>
                    <td>${row['Risk Score']}</td>
                `;
                historyBody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error('Error loading history:', err);
    }
}

document.addEventListener('DOMContentLoaded', loadHistory);
document.getElementById('refresh-history-btn')?.addEventListener('click', loadHistory);

