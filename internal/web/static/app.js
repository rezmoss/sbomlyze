// State
let treeData = [];
let originalTreeData = [];  // Store original data for filtering
let selectedComponentId = null;
let expandedNodes = new Set();
let currentSearchQuery = '';
let currentComponentDetail = null;  // Store current component detail for view toggle
let showRawJson = false;  // Toggle between detail and raw JSON view
let treeOffset = 0;
let treeTotal = 0;
let loadingMore = false;
let searchTotal = 0;
let searchResultCount = 0;

// DOM Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const mainContent = document.getElementById('main-content');
const treeContainer = document.getElementById('tree-container');
const detailContainer = document.getElementById('detail-container');
const statsContainer = document.getElementById('stats-container');
const searchInput = document.getElementById('search-input');
const uploadNewBtn = document.getElementById('upload-new');

// Event Listeners
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', handleDragOver);
dropZone.addEventListener('dragleave', handleDragLeave);
dropZone.addEventListener('drop', handleDrop);
fileInput.addEventListener('change', handleFileSelect);
searchInput.addEventListener('input', debounce(handleSearch, 200));
uploadNewBtn.addEventListener('click', resetUI);

function handleDragOver(e) {
    e.preventDefault();
    dropZone.classList.add('dragover');
}

function handleDragLeave(e) {
    e.preventDefault();
    dropZone.classList.remove('dragover');
}

function handleDrop(e) {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        uploadFile(files[0]);
    }
}

function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        uploadFile(files[0]);
    }
}

function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    // Show progress bar
    dropZone.innerHTML = `
        <div class="drop-content">
            <p>Uploading...</p>
            <div class="progress-container">
                <div class="progress-bar">
                    <div class="progress-fill" id="upload-progress-fill"></div>
                </div>
                <div class="progress-text" id="upload-progress-text">0%</div>
            </div>
        </div>
    `;

    const xhr = new XMLHttpRequest();

    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 100);
            const fill = document.getElementById('upload-progress-fill');
            const text = document.getElementById('upload-progress-text');
            if (fill) fill.style.width = pct + '%';
            if (text) text.textContent = pct + '%';
        }
    };

    xhr.onload = function() {
        if (xhr.status === 200) {
            const text = document.getElementById('upload-progress-text');
            const fill = document.getElementById('upload-progress-fill');
            if (text) text.textContent = 'Processing...';
            if (fill) fill.style.width = '100%';

            try {
                const result = JSON.parse(xhr.responseText);
                console.log('Upload result:', result);

                dropZone.classList.add('hidden');
                mainContent.classList.remove('hidden');

                Promise.all([loadTree(), loadStats()]);
            } catch (e) {
                showUploadError(e.message);
            }
        } else {
            showUploadError(xhr.responseText || 'Upload failed');
        }
    };

    xhr.onerror = function() {
        showUploadError('Network error during upload');
    };

    xhr.open('POST', '/api/upload');
    xhr.send(formData);
}

function showUploadError(message) {
    dropZone.innerHTML = `
        <div class="drop-content">
            <p style="color: var(--accent);">Error: ${escapeHtml(message)}</p>
            <p class="hint">Click to try again</p>
        </div>
    `;
}

async function loadTree() {
    try {
        treeOffset = 0;
        treeTotal = 0;

        const response = await fetch('/api/tree?offset=0&limit=200');
        if (!response.ok) throw new Error('Failed to load tree');

        const data = await response.json();
        originalTreeData = data.nodes || [];
        treeTotal = data.total || 0;
        treeOffset = originalTreeData.length;
        treeData = originalTreeData;
        renderTree();

        // Attach scroll listener for infinite scroll
        treeContainer.removeEventListener('scroll', handleTreeScroll);
        treeContainer.addEventListener('scroll', handleTreeScroll);
    } catch (error) {
        console.error('Load tree error:', error);
        treeContainer.innerHTML = '<p class="placeholder">Failed to load components</p>';
    }
}

function handleTreeScroll() {
    if (loadingMore || currentSearchQuery) return;
    if (treeOffset >= treeTotal) return;

    const { scrollTop, scrollHeight, clientHeight } = treeContainer;
    if (scrollTop + clientHeight >= scrollHeight - 100) {
        loadMoreTree();
    }
}

async function loadMoreTree() {
    if (loadingMore || treeOffset >= treeTotal) return;
    loadingMore = true;

    // Show loading indicator
    const loadMoreEl = document.createElement('div');
    loadMoreEl.className = 'load-more';
    loadMoreEl.textContent = 'Loading more...';
    treeContainer.appendChild(loadMoreEl);

    try {
        const response = await fetch(`/api/tree?offset=${treeOffset}&limit=200`);
        if (!response.ok) throw new Error('Failed to load more');

        const data = await response.json();
        const newNodes = data.nodes || [];

        // Append to data arrays
        originalTreeData = originalTreeData.concat(newNodes);
        treeData = originalTreeData;
        treeOffset += newNodes.length;

        // Remove loading indicator
        loadMoreEl.remove();

        // Append new nodes to DOM
        appendTreeNodes(newNodes);
    } catch (error) {
        console.error('Load more error:', error);
        loadMoreEl.textContent = 'Failed to load more';
    } finally {
        loadingMore = false;
    }
}

function appendTreeNodes(nodes) {
    const html = nodes.map(node => renderTreeNode(node, 0)).join('');
    const temp = document.createElement('div');
    temp.innerHTML = html;

    while (temp.firstChild) {
        const child = temp.firstChild;
        treeContainer.appendChild(child);

        const items = child.querySelectorAll ? child.querySelectorAll('.tree-item') : [];
        items.forEach(item => {
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = item.dataset.id;
                const hasChildren = item.dataset.hasChildren === 'true';
                if (hasChildren) toggleNode(id);
                selectComponent(id);
            });
        });
    }
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error('Failed to load stats');

        const data = await response.json();
        renderStats(data);
    } catch (error) {
        console.error('Load stats error:', error);
        statsContainer.innerHTML = '<p class="placeholder">Failed to load statistics</p>';
    }
}

function renderTree() {
    if (treeData.length === 0) {
        if (currentSearchQuery) {
            treeContainer.innerHTML = '<p class="placeholder">No matching components</p>';
        } else {
            treeContainer.innerHTML = '<p class="placeholder">No components found</p>';
        }
        return;
    }

    // Show result count when filtering
    let headerHtml = '';
    if (currentSearchQuery) {
        if (searchTotal > searchResultCount) {
            headerHtml = `<div class="filter-info">Showing ${searchResultCount} of ${searchTotal} results for "${escapeHtml(currentSearchQuery)}" <span class="filter-hint">(searching all fields)</span></div>`;
        } else {
            headerHtml = `<div class="filter-info">${treeData.length} result${treeData.length !== 1 ? 's' : ''} for "${escapeHtml(currentSearchQuery)}" <span class="filter-hint">(searching all fields)</span></div>`;
        }
    }

    const html = headerHtml + treeData.map(node => renderTreeNode(node, 0)).join('');
    treeContainer.innerHTML = html;

    // Add click handlers
    treeContainer.querySelectorAll('.tree-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.stopPropagation();
            const id = item.dataset.id;
            const hasChildren = item.dataset.hasChildren === 'true';

            // Toggle expand/collapse if has children
            if (hasChildren) {
                toggleNode(id);
            }

            // Select and show details
            selectComponent(id);
        });
    });
}

function renderTreeNode(node, depth) {
    const isExpanded = expandedNodes.has(node.id);
    const hasChildren = node.hasChildren || (node.children && node.children.length > 0);
    const isSelected = node.id === selectedComponentId;

    // Highlight matching text
    let displayName = escapeHtml(node.name);
    let displayVersion = escapeHtml(node.version || '');
    if (currentSearchQuery) {
        displayName = highlightMatch(node.name, currentSearchQuery);
        displayVersion = highlightMatch(node.version || '', currentSearchQuery);
    }

    let html = `
        <div class="tree-node">
            <div class="tree-item ${isSelected ? 'selected' : ''}"
                 data-id="${escapeHtml(node.id)}"
                 data-has-children="${hasChildren}">
                <span class="tree-toggle ${hasChildren ? (isExpanded ? 'expanded' : '') : 'no-children'}">
                    ${hasChildren ? '>' : ''}
                </span>
                <span class="tree-name">${displayName}</span>
                <span class="tree-version">${displayVersion}</span>
                <span class="tree-type">${escapeHtml(node.type || 'unknown')}</span>
            </div>
    `;

    if (hasChildren && isExpanded && node.children && node.children.length > 0) {
        html += '<div class="tree-node-children">';
        html += node.children.map(child => renderTreeNode(child, depth + 1)).join('');
        html += '</div>';
    }

    html += '</div>';
    return html;
}

function highlightMatch(text, query) {
    if (!text || !query) return escapeHtml(text);
    const escaped = escapeHtml(text);
    const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
    return escaped.replace(regex, '<mark>$1</mark>');
}

function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function toggleNode(id) {
    if (expandedNodes.has(id)) {
        expandedNodes.delete(id);
    } else {
        expandedNodes.add(id);
    }
    renderTree();
}

async function selectComponent(id) {
    selectedComponentId = id;
    showRawJson = false;  // Reset to detail view when selecting new component

    // Update selection in tree
    treeContainer.querySelectorAll('.tree-item').forEach(item => {
        item.classList.toggle('selected', item.dataset.id === id);
    });

    // Load component details
    try {
        const response = await fetch(`/api/component/${encodeURIComponent(id)}`);
        if (!response.ok) throw new Error('Failed to load component');

        const detail = await response.json();
        renderDetail(detail);
    } catch (error) {
        console.error('Load component error:', error);
        detailContainer.innerHTML = '<p class="placeholder">Failed to load component details</p>';
    }
}

function renderDetail(detail) {
    currentComponentDetail = detail;

    // View toggle buttons
    let html = `
        <div class="view-toggle">
            <button class="toggle-btn ${!showRawJson ? 'active' : ''}" onclick="switchToDetailView()">Details</button>
            <button class="toggle-btn ${showRawJson ? 'active' : ''}" onclick="switchToJsonView()" ${!detail.rawJson ? 'disabled title="No raw JSON available"' : ''}>Raw JSON</button>
        </div>
    `;

    if (showRawJson && detail.rawJson) {
        // Show formatted raw JSON with syntax highlighting
        let formattedJson;
        try {
            formattedJson = JSON.stringify(detail.rawJson, null, 2);
        } catch (e) {
            formattedJson = String(detail.rawJson);
        }
        html += `
            <div class="json-viewer">
                <pre><code>${syntaxHighlightJson(formattedJson)}</code></pre>
            </div>
        `;
    } else {
        // Show detail view
        html += `
            <div class="detail-section">
                <h3>Name</h3>
                <div class="detail-value">${escapeHtml(detail.name)}</div>
            </div>

            <div class="detail-section">
                <h3>Version</h3>
                <div class="detail-value">${escapeHtml(detail.version || 'N/A')}</div>
            </div>

            <div class="detail-section">
                <h3>Type</h3>
                <div class="detail-value">${escapeHtml(detail.type || 'unknown')}</div>
            </div>
        `;

        if (detail.purl) {
            html += `
                <div class="detail-section">
                    <h3>PURL</h3>
                    <div class="detail-value" style="font-family: monospace; font-size: 0.9rem;">${escapeHtml(detail.purl)}</div>
                </div>
            `;
        }

        if (detail.supplier) {
            html += `
                <div class="detail-section">
                    <h3>Supplier</h3>
                    <div class="detail-value">${escapeHtml(detail.supplier)}</div>
                </div>
            `;
        }

        if (detail.licenses && detail.licenses.length > 0) {
            html += `
                <div class="detail-section">
                    <h3>Licenses</h3>
                    <ul class="detail-list">
                        ${detail.licenses.map(lic => `<li>${escapeHtml(lic)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (detail.hashes && Object.keys(detail.hashes).length > 0) {
            html += `
                <div class="detail-section">
                    <h3>Hashes</h3>
                    <ul class="detail-list">
                        ${Object.entries(detail.hashes).map(([algo, value]) => `
                            <li class="hash-item">
                                <span class="hash-algo">${escapeHtml(algo)}</span>
                                <span class="hash-value">${escapeHtml(value)}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `;
        }

        if (detail.dependencies && detail.dependencies.length > 0) {
            html += `
                <div class="detail-section">
                    <h3>Dependencies (${detail.dependencies.length})</h3>
                    <ul class="detail-list">
                        ${detail.dependencies.slice(0, 20).map(dep => `<li>${escapeHtml(dep)}</li>`).join('')}
                        ${detail.dependencies.length > 20 ? `<li>... and ${detail.dependencies.length - 20} more</li>` : ''}
                    </ul>
                </div>
            `;
        }
    }

    detailContainer.innerHTML = html;
}

function switchToDetailView() {
    showRawJson = false;
    if (currentComponentDetail) {
        renderDetail(currentComponentDetail);
    }
}

function switchToJsonView() {
    showRawJson = true;
    if (currentComponentDetail) {
        renderDetail(currentComponentDetail);
    }
}

function renderStats(data) {
    const stats = data.stats;
    const info = data.info;
    const coverage = data.coverage;
    const relationships = data.relationships;

    let html = '';

    // SBOM Info
    if (info && (info.os_name || info.source_name)) {
        html += '<div class="info-banner">';
        if (info.os_name) {
            html += `<p><strong>OS:</strong> ${escapeHtml(info.os_name)} ${escapeHtml(info.os_version || '')}</p>`;
        }
        if (info.source_name) {
            html += `<p><strong>Source:</strong> ${escapeHtml(info.source_name)}</p>`;
        }
        if (info.source_type) {
            html += `<p><strong>Type:</strong> ${escapeHtml(info.source_type)}</p>`;
        }
        html += '</div>';
    }

    // Overview stats
    html += `
        <div class="stat-item">
            <span class="stat-label">Total Components</span>
            <span class="stat-value">${stats.total_components || 0}</span>
        </div>
    `;

    // Coverage percentages (quality metrics)
    if (coverage) {
        html += '<div class="stat-group"><h4>Data Quality</h4>';
        html += renderCoverageBar('PURL Coverage', coverage.purl_percent);
        html += renderCoverageBar('CPE Coverage', coverage.cpe_percent);
        html += renderCoverageBar('License Coverage', coverage.license_percent);
        html += renderCoverageBar('Hash Coverage', coverage.hash_percent);
        html += '</div>';
    }

    // Package types
    if (stats.by_type && Object.keys(stats.by_type).length > 0) {
        html += '<div class="stat-group"><h4>By Package Type</h4>';
        html += renderStatBars(stats.by_type, 10);
        html += '</div>';
    }

    // By Language (if available)
    if (stats.by_language && Object.keys(stats.by_language).length > 0) {
        html += '<div class="stat-group"><h4>By Language</h4>';
        html += renderStatBars(stats.by_language, 10);
        html += '</div>';
    }

    // By Scanner/FoundBy (if available)
    if (stats.by_found_by && Object.keys(stats.by_found_by).length > 0) {
        html += '<div class="stat-group"><h4>By Scanner</h4>';
        html += renderStatBars(stats.by_found_by, 8);
        html += '</div>';
    }

    // License Categories
    if (stats.license_categories) {
        const lc = stats.license_categories;
        const total = lc.copyleft + lc.permissive + lc.public_domain + lc.unknown;
        if (total > 0) {
            html += '<div class="stat-group"><h4>License Categories</h4>';
            const categories = {
                'Copyleft (GPL, LGPL...)': lc.copyleft,
                'Permissive (MIT, BSD...)': lc.permissive,
                'Public Domain': lc.public_domain,
                'Unknown/Other': lc.unknown
            };
            html += renderStatBars(categories, 4);
            html += '</div>';
        }
    }

    // Relationships (Syft format only)
    if (relationships && Object.keys(relationships).length > 0) {
        html += '<div class="stat-group"><h4>Relationships</h4>';
        html += renderStatBars(relationships, 5);
        html += '</div>';
    }

    // Detailed counts
    html += '<div class="stat-group"><h4>Detailed Counts</h4>';
    html += `
        <div class="stat-item-small">
            <span class="stat-label">With License</span>
            <span class="stat-value">${(stats.total_components || 0) - (stats.without_license || 0)}</span>
        </div>
        <div class="stat-item-small">
            <span class="stat-label">Without License</span>
            <span class="stat-value ${stats.without_license > 0 ? 'warning' : ''}">${stats.without_license || 0}</span>
        </div>
        <div class="stat-item-small">
            <span class="stat-label">With CPEs</span>
            <span class="stat-value">${stats.with_cpes || 0}</span>
        </div>
        <div class="stat-item-small">
            <span class="stat-label">Without CPEs</span>
            <span class="stat-value ${stats.without_cpes > 0 ? 'warning' : ''}">${stats.without_cpes || 0}</span>
        </div>
        <div class="stat-item-small">
            <span class="stat-label">With Hashes</span>
            <span class="stat-value">${stats.with_hashes || 0}</span>
        </div>
        <div class="stat-item-small">
            <span class="stat-label">With Dependencies</span>
            <span class="stat-value">${stats.with_dependencies || 0}</span>
        </div>
        <div class="stat-item-small">
            <span class="stat-label">Total Dependencies</span>
            <span class="stat-value">${stats.total_dependencies || 0}</span>
        </div>
    `;
    html += '</div>';

    // Duplicates warning
    if (stats.duplicate_count > 0) {
        html += `
            <div class="stat-item warning-item">
                <span class="stat-label">Duplicates Found</span>
                <span class="stat-value">${stats.duplicate_count}</span>
            </div>
        `;
    }

    statsContainer.innerHTML = html;
}

function renderStatBars(data, limit) {
    const sortedEntries = Object.entries(data)
        .sort((a, b) => b[1] - a[1])
        .slice(0, limit);

    if (sortedEntries.length === 0) return '';

    const maxCount = sortedEntries[0][1];
    let html = '';

    for (const [label, count] of sortedEntries) {
        const percentage = (count / maxCount) * 100;
        html += `
            <div class="stat-bar">
                <span class="stat-bar-label">${escapeHtml(label)}</span>
                <div class="stat-bar-fill">
                    <div class="stat-bar-fill-inner" style="width: ${percentage}%"></div>
                </div>
                <span class="stat-bar-value">${count}</span>
            </div>
        `;
    }

    const remaining = Object.keys(data).length - limit;
    if (remaining > 0) {
        html += `<div class="stat-more">+${remaining} more</div>`;
    }

    return html;
}

function renderCoverageBar(label, percent) {
    const safePercent = Math.min(100, Math.max(0, percent || 0));
    const colorClass = safePercent >= 80 ? 'coverage-good' : safePercent >= 50 ? 'coverage-medium' : 'coverage-low';

    return `
        <div class="coverage-bar">
            <span class="coverage-label">${escapeHtml(label)}</span>
            <div class="coverage-track">
                <div class="coverage-fill ${colorClass}" style="width: ${safePercent}%"></div>
            </div>
            <span class="coverage-percent">${safePercent.toFixed(1)}%</span>
        </div>
    `;
}

async function handleSearch() {
    const query = searchInput.value.trim();
    currentSearchQuery = query.toLowerCase();

    if (query.length === 0) {
        // Reset to original data
        treeData = originalTreeData;
        searchTotal = 0;
        searchResultCount = 0;
        renderTree();
        return;
    }

    // Use server-side search for deep search across all fields (like TUI mode)
    try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
        if (!response.ok) throw new Error('Search failed');

        const data = await response.json();
        const results = data.results || [];
        searchTotal = data.total || 0;
        searchResultCount = results.length;

        // Convert search results to tree format
        treeData = results.map(result => ({
            id: result.id,
            name: result.name,
            version: result.version,
            type: result.type,
            hasChildren: false,
            children: []
        }));

        renderTree();
    } catch (error) {
        console.error('Search error:', error);
        // Fallback to client-side filtering
        treeData = filterTreeLocal(originalTreeData, currentSearchQuery);
        searchTotal = 0;
        searchResultCount = 0;
        renderTree();
    }
}

function filterTreeLocal(nodes, query) {
    const results = [];

    for (const node of nodes) {
        // Check if this node matches
        const nameMatch = node.name && node.name.toLowerCase().includes(query);
        const versionMatch = node.version && node.version.toLowerCase().includes(query);
        const typeMatch = node.type && node.type.toLowerCase().includes(query);
        const idMatch = node.id && node.id.toLowerCase().includes(query);

        if (nameMatch || versionMatch || typeMatch || idMatch) {
            results.push({
                ...node,
                children: node.children ? filterTreeLocal(node.children, query) : [],
                hasChildren: node.hasChildren
            });
        } else if (node.children && node.children.length > 0) {
            const matchingChildren = filterTreeLocal(node.children, query);
            if (matchingChildren.length > 0) {
                results.push({
                    ...node,
                    children: matchingChildren,
                    hasChildren: true
                });
                expandedNodes.add(node.id);
            }
        }
    }

    return results;
}

function resetUI() {
    mainContent.classList.add('hidden');
    dropZone.classList.remove('hidden');
    dropZone.innerHTML = `
        <div class="drop-content">
            <svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="17,8 12,3 7,8"></polyline>
                <line x1="12" y1="3" x2="12" y2="15"></line>
            </svg>
            <p>Drag & drop an SBOM file here</p>
            <p class="hint">or click to select (CycloneDX, SPDX, Syft JSON)</p>
            <input type="file" id="file-input" accept=".json" hidden>
        </div>
    `;

    // Re-attach file input handler
    const newFileInput = document.getElementById('file-input');
    newFileInput.addEventListener('change', handleFileSelect);

    treeData = [];
    originalTreeData = [];
    selectedComponentId = null;
    expandedNodes.clear();
    currentSearchQuery = '';
    currentComponentDetail = null;
    showRawJson = false;
    treeOffset = 0;
    treeTotal = 0;
    loadingMore = false;
    searchTotal = 0;
    searchResultCount = 0;
    searchInput.value = '';
    detailContainer.innerHTML = '<p class="placeholder">Select a component to view details</p>';
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function syntaxHighlightJson(json) {
    // Escape HTML first
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // Apply syntax highlighting
    return json.replace(
        /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
        function (match) {
            let cls = 'json-number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'json-key';
                    // Remove the colon for styling, we'll add it back
                    match = match.slice(0, -1);
                    return '<span class="' + cls + '">' + match + '</span>:';
                } else {
                    cls = 'json-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'json-boolean';
            } else if (/null/.test(match)) {
                cls = 'json-null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        }
    );
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
