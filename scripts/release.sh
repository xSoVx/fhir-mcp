#!/bin/bash

# FhirMCP Release Script
# Automates version bumping, tagging, and release preparation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    print_error "Not in a git repository"
    exit 1
fi

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    print_error "Working directory is not clean. Please commit or stash changes first."
    git status --short
    exit 1
fi

# Get the current version from package.json
CURRENT_VERSION=$(node -p "require('./package.json').version")
print_status "Current version: $CURRENT_VERSION"

# Ask for new version
echo "Select version bump type:"
echo "1) patch (bug fixes) - $CURRENT_VERSION -> $(node -p "require('semver').inc('$CURRENT_VERSION', 'patch')" 2>/dev/null || echo "x.x.x")"
echo "2) minor (new features) - $CURRENT_VERSION -> $(node -p "require('semver').inc('$CURRENT_VERSION', 'minor')" 2>/dev/null || echo "x.x.x")"
echo "3) major (breaking changes) - $CURRENT_VERSION -> $(node -p "require('semver').inc('$CURRENT_VERSION', 'major')" 2>/dev/null || echo "x.x.x")"
echo "4) custom version"
echo "5) exit"

read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        VERSION_TYPE="patch"
        ;;
    2)
        VERSION_TYPE="minor"
        ;;
    3)
        VERSION_TYPE="major"
        ;;
    4)
        read -p "Enter custom version (e.g., 1.0.0): " CUSTOM_VERSION
        if [[ ! $CUSTOM_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            print_error "Invalid version format. Use semantic versioning (x.y.z)"
            exit 1
        fi
        NEW_VERSION=$CUSTOM_VERSION
        ;;
    5)
        print_status "Release cancelled"
        exit 0
        ;;
    *)
        print_error "Invalid choice"
        exit 1
        ;;
esac

# Calculate new version if not custom
if [ -z "$NEW_VERSION" ]; then
    # Try to use semver if available, otherwise do basic increment
    if command -v node >/dev/null 2>&1; then
        NEW_VERSION=$(node -e "
        const semver = require('semver');
        console.log(semver.inc('$CURRENT_VERSION', '$VERSION_TYPE'));
        " 2>/dev/null || echo "")
    fi
    
    # Fallback to basic increment if semver not available
    if [ -z "$NEW_VERSION" ]; then
        IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
        case $VERSION_TYPE in
            patch)
                VERSION_PARTS[2]=$((VERSION_PARTS[2] + 1))
                ;;
            minor)
                VERSION_PARTS[1]=$((VERSION_PARTS[1] + 1))
                VERSION_PARTS[2]=0
                ;;
            major)
                VERSION_PARTS[0]=$((VERSION_PARTS[0] + 1))
                VERSION_PARTS[1]=0
                VERSION_PARTS[2]=0
                ;;
        esac
        NEW_VERSION="${VERSION_PARTS[0]}.${VERSION_PARTS[1]}.${VERSION_PARTS[2]}"
    fi
fi

print_status "New version will be: $NEW_VERSION"

# Confirm the release
read -p "Continue with release v$NEW_VERSION? (y/N): " confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
    print_status "Release cancelled"
    exit 0
fi

# Update version in package.json files
print_status "Updating package.json files..."
npm version $NEW_VERSION --no-git-tag-version

if [ -f "packages/mcp-fhir-server/package.json" ]; then
    cd packages/mcp-fhir-server
    npm version $NEW_VERSION --no-git-tag-version
    cd ../..
fi

# Build the project
print_status "Building project..."
npm run build

# Run tests
print_status "Running tests..."
npm run typecheck
node test-basic-functionality.js || {
    print_error "Tests failed. Aborting release."
    exit 1
}

# Get commit message
read -p "Enter release description (optional): " RELEASE_DESC

# Create commit
COMMIT_MSG="chore: Release v$NEW_VERSION"
if [ -n "$RELEASE_DESC" ]; then
    COMMIT_MSG="$COMMIT_MSG

$RELEASE_DESC

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"
else
    COMMIT_MSG="$COMMIT_MSG

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"
fi

git add .
git commit -m "$COMMIT_MSG"

# Create tag
TAG_MSG="Release v$NEW_VERSION"
if [ -n "$RELEASE_DESC" ]; then
    TAG_MSG="$TAG_MSG

$RELEASE_DESC"
fi

git tag -a "v$NEW_VERSION" -m "$TAG_MSG"

print_success "Release v$NEW_VERSION created successfully!"
print_status "Next steps:"
echo "1. Review the changes: git show"
echo "2. Push to remote: git push && git push --tags"
echo "3. Create GitHub release from the tag"

print_status "Git log:"
git log --oneline -5