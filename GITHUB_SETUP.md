# GitHub Repository Setup Instructions

Follow these steps to create and configure the FhirMCP repository on GitHub.

## 1. Create GitHub Repository

### Option A: Using GitHub Web Interface

1. Go to [GitHub](https://github.com) and sign in
2. Click the "+" icon in the top right corner
3. Select "New repository"
4. Configure the repository:
   - **Repository name**: `fhir-mcp`
   - **Description**: `MCP server for FHIR and HL7 terminology services with PHI protection`
   - **Visibility**: Public (recommended for open source)
   - **Initialize**: Do NOT initialize with README, .gitignore, or license (we already have these)
5. Click "Create repository"

### Option B: Using GitHub CLI (if available)

```bash
gh repo create fhir-mcp --public --description "MCP server for FHIR and HL7 terminology services with PHI protection"
```

## 2. Add Remote and Push

After creating the repository, add it as remote and push:

```bash
# Add the remote (replace 'yourusername' with your GitHub username)
git remote add origin https://github.com/yourusername/fhir-mcp.git

# Push the code and tags
git push -u origin master
git push --tags
```

## 3. Configure Repository Settings

### Branches
1. Go to **Settings → Branches**
2. Add branch protection rule for `master`:
   - Require status checks to pass
   - Require branches to be up to date before merging
   - Include administrators

### Actions
1. Go to **Settings → Actions → General**
2. Set "Actions permissions" to "Allow all actions and reusable workflows"
3. Enable "Allow GitHub Actions to create and approve pull requests"

### Releases
The repository is configured with automated release workflows:
- Releases are created automatically when you push version tags
- Release notes are generated from CHANGELOG.md
- Build artifacts are uploaded

## 4. Repository Topics and About

1. Go to the repository main page
2. Click the gear icon next to "About"
3. Add topics: `fhir`, `mcp`, `healthcare`, `interoperability`, `llm`, `typescript`
4. Set website to documentation URL if hosting docs separately
5. Enable "Packages" and "Environments" if needed

## 5. Security Settings

1. Go to **Settings → Security & analysis**
2. Enable:
   - Dependency graph
   - Dependabot alerts
   - Dependabot security updates
   - Code scanning alerts

## 6. Release Process

### Automated Release (Recommended)
Use the provided release script:

```bash
# Run the interactive release script
./scripts/release.sh
```

This will:
- Prompt for version type (patch/minor/major)
- Update package.json versions
- Run tests to ensure quality
- Create commit and tag
- Provide instructions for pushing

### Manual Release
```bash
# Update version
npm version patch  # or minor/major

# Create tag
git tag -a v1.0.1 -m "Release v1.0.1: Description"

# Push
git push && git push --tags
```

## 7. Issue Templates

Consider adding issue templates in `.github/ISSUE_TEMPLATE/`:

- `bug_report.md` - For bug reports
- `feature_request.md` - For feature requests  
- `question.md` - For usage questions

## 8. Contributing Guidelines

Add `CONTRIBUTING.md` with:
- Code of conduct
- Development setup instructions
- Pull request process
- Coding standards

## 9. Monitoring

Set up repository monitoring:
- Enable notifications for releases and security alerts
- Consider setting up project boards for issue tracking
- Monitor CI/CD pipeline health

## Next Steps After Setup

1. **Update README**: Replace `yourusername` with actual GitHub username
2. **Test CI**: Create a test branch and PR to verify workflows
3. **Create first release**: Tag v0.1.0 should trigger release workflow
4. **Documentation**: Consider hosting docs on GitHub Pages
5. **Community**: Add to MCP registry lists and healthcare dev communities

The repository is now ready for collaborative development with automated testing, releases, and proper documentation!