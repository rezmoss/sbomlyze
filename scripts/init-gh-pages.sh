#!/bin/bash
# Initialize gh-pages branch for package repository
# Run this once to set up the branch

set -e

echo "Creating gh-pages branch for package repository..."

# Save current branch
CURRENT_BRANCH=$(git branch --show-current)

# Create orphan branch
git checkout --orphan gh-pages

# Remove all files
git rm -rf . 2>/dev/null || true

# Create directory structure
mkdir -p deb/pool/main
mkdir -p deb/dists/stable/main/binary-amd64
mkdir -p deb/dists/stable/main/binary-arm64
mkdir -p deb/dists/stable/main/binary-i386
mkdir -p rpm/packages
mkdir -p apk/packages/x86_64
mkdir -p apk/packages/aarch64
mkdir -p apk/packages/x86

# Create placeholder files
touch deb/pool/main/.gitkeep
touch deb/dists/stable/main/binary-amd64/.gitkeep
touch deb/dists/stable/main/binary-arm64/.gitkeep
touch deb/dists/stable/main/binary-i386/.gitkeep
touch rpm/packages/.gitkeep
touch apk/packages/x86_64/.gitkeep
touch apk/packages/aarch64/.gitkeep
touch apk/packages/x86/.gitkeep

# Create initial index page
cat > index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <title>sbomlyze Package Repository</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
    h1 { color: #333; }
    h2 { color: #666; margin-top: 30px; }
    pre { background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }
    code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
    .note { background: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; }
  </style>
</head>
<body>
  <h1>sbomlyze Package Repository</h1>
  <p>A fast, reliable SBOM diff and analysis tool.</p>

  <h2>Debian / Ubuntu (apt)</h2>
  <pre>
# Add repository
echo "deb [trusted=yes] https://rezmoss.github.io/sbomlyze/deb stable main" | sudo tee /etc/apt/sources.list.d/sbomlyze.list

# Install
sudo apt update
sudo apt install sbomlyze</pre>

  <h2>RHEL / Fedora / CentOS (dnf/yum)</h2>
  <pre>
# Add repository
sudo tee /etc/yum.repos.d/sbomlyze.repo &lt;&lt; 'REPO'
[sbomlyze]
name=sbomlyze
baseurl=https://rezmoss.github.io/sbomlyze/rpm/packages
enabled=1
gpgcheck=0
REPO

# Install
sudo dnf install sbomlyze</pre>

  <h2>Alpine (apk)</h2>
  <pre>
# Download and install directly
wget https://github.com/rezmoss/sbomlyze/releases/latest/download/sbomlyze_VERSION_linux_amd64.apk
sudo apk add --allow-untrusted sbomlyze_VERSION_linux_amd64.apk</pre>
  <p class="note">Note: Alpine repository requires signed packages. Use direct download for now.</p>

  <h2>Other Installation Methods</h2>
  <pre>
# Install script (recommended)
curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sh

# Go install
go install github.com/rezmoss/sbomlyze/cmd/sbomlyze@latest</pre>

  <p>See <a href="https://github.com/rezmoss/sbomlyze">GitHub repository</a> for more information.</p>
</body>
</html>
EOF

# Create .nojekyll to disable Jekyll processing
touch .nojekyll

# Commit
git add -A
git commit -m "Initialize package repository"

echo ""
echo "gh-pages branch created locally."
echo ""
echo "To push to GitHub:"
echo "  git push -u origin gh-pages"
echo ""
echo "Then enable GitHub Pages in repository settings:"
echo "  Settings -> Pages -> Source: Deploy from branch -> Branch: gh-pages"
echo ""

# Return to original branch
git checkout "$CURRENT_BRANCH"
