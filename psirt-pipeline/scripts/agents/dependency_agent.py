#!/usr/bin/env python3
"""
Dependency Analysis Agent
Analyzes project dependencies for known vulnerabilities
"""

import os
import json
import re
from typing import Dict, List, Any
from pathlib import Path


class DependencyAgent:
    """Agent for analyzing dependencies and detecting vulnerable packages"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.supported_files = {
            'package.json': self._parse_npm,
            'package-lock.json': self._parse_npm_lock,
            'pom.xml': self._parse_maven,
            'build.gradle': self._parse_gradle,
            'requirements.txt': self._parse_python,
            'Pipfile': self._parse_pipfile,
            'go.mod': self._parse_go,
            'Cargo.toml': self._parse_rust,
            'composer.json': self._parse_php
        }
    
    def scan(self, changed_files: List[str]) -> Dict[str, Any]:
        """
        Scan changed files for dependency information
        
        Args:
            changed_files: List of file paths that changed in PR
            
        Returns:
            Dictionary containing dependency analysis results
        """
        dependencies = []
        dependency_files = []
        
        # Identify dependency files
        for file_path in changed_files:
            filename = os.path.basename(file_path)
            if filename in self.supported_files:
                dependency_files.append(file_path)
                
                # Parse the dependency file
                if os.path.exists(file_path):
                    parser = self.supported_files[filename]
                    deps = parser(file_path)
                    dependencies.extend(deps)
        
        # Remove duplicates
        unique_deps = self._deduplicate_dependencies(dependencies)
        
        # Analyze with AI
        ai_analysis = self._ai_analyze_dependencies(unique_deps)
        
        return {
            'dependency_files': dependency_files,
            'dependencies': unique_deps,
            'total_count': len(unique_deps),
            'ai_analysis': ai_analysis,
            'risk_flags': self._identify_risk_flags(unique_deps)
        }
    
    def _parse_npm(self, file_path: str) -> List[Dict[str, str]]:
        """Parse package.json for npm dependencies"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            deps = []
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        deps.append({
                            'name': name,
                            'version': version.lstrip('^~>=<'),
                            'type': 'npm',
                            'file': file_path
                        })
            return deps
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return []
    
    def _parse_npm_lock(self, file_path: str) -> List[Dict[str, str]]:
        """Parse package-lock.json"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            deps = []
            if 'packages' in data:
                for pkg_path, pkg_info in data['packages'].items():
                    if pkg_path and 'version' in pkg_info:
                        name = pkg_path.split('node_modules/')[-1]
                        deps.append({
                            'name': name,
                            'version': pkg_info['version'],
                            'type': 'npm',
                            'file': file_path
                        })
            return deps
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return []
    
    def _parse_maven(self, file_path: str) -> List[Dict[str, str]]:
        """Parse pom.xml for Maven dependencies"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            deps = []
            # Simple regex parsing (in production, use XML parser)
            pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
            matches = re.findall(pattern, content, re.DOTALL)
            
            for group_id, artifact_id, version in matches:
                deps.append({
                    'name': f"{group_id.strip()}:{artifact_id.strip()}",
                    'version': version.strip(),
                    'type': 'maven',
                    'file': file_path
                })
            return deps
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return []
    
    def _parse_gradle(self, file_path: str) -> List[Dict[str, str]]:
        """Parse build.gradle for Gradle dependencies"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            deps = []
            # Match implementation/compile dependencies
            pattern = r'(?:implementation|compile|api)\s+["\']([^:]+):([^:]+):([^"\']+)["\']'
            matches = re.findall(pattern, content)
            
            for group, artifact, version in matches:
                deps.append({
                    'name': f"{group}:{artifact}",
                    'version': version,
                    'type': 'gradle',
                    'file': file_path
                })
            return deps
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return []
    
    def _parse_python(self, file_path: str) -> List[Dict[str, str]]:
        """Parse requirements.txt for Python dependencies"""
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            deps = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package==version or package>=version
                    match = re.match(r'([a-zA-Z0-9_-]+)([>=<~!]+)([0-9.]+)', line)
                    if match:
                        deps.append({
                            'name': match.group(1),
                            'version': match.group(3),
                            'type': 'python',
                            'file': file_path
                        })
            return deps
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return []
    
    def _parse_pipfile(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Pipfile for Python dependencies"""
        # Simplified - in production use toml parser
        return self._parse_python(file_path)
    
    def _parse_go(self, file_path: str) -> List[Dict[str, str]]:
        """Parse go.mod for Go dependencies"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            deps = []
            pattern = r'require\s+([^\s]+)\s+v([0-9.]+)'
            matches = re.findall(pattern, content)
            
            for name, version in matches:
                deps.append({
                    'name': name,
                    'version': version,
                    'type': 'go',
                    'file': file_path
                })
            return deps
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return []
    
    def _parse_rust(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Cargo.toml for Rust dependencies"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            deps = []
            pattern = r'([a-zA-Z0-9_-]+)\s*=\s*"([0-9.]+)"'
            matches = re.findall(pattern, content)
            
            for name, version in matches:
                deps.append({
                    'name': name,
                    'version': version,
                    'type': 'rust',
                    'file': file_path
                })
            return deps
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return []
    
    def _parse_php(self, file_path: str) -> List[Dict[str, str]]:
        """Parse composer.json for PHP dependencies"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            deps = []
            for dep_type in ['require', 'require-dev']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        if name != 'php':  # Skip PHP version requirement
                            deps.append({
                                'name': name,
                                'version': version.lstrip('^~>=<'),
                                'type': 'php',
                                'file': file_path
                            })
            return deps
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return []
    
    def _deduplicate_dependencies(self, dependencies: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Remove duplicate dependencies"""
        seen = set()
        unique = []
        
        for dep in dependencies:
            key = f"{dep['name']}:{dep['version']}:{dep['type']}"
            if key not in seen:
                seen.add(key)
                unique.append(dep)
        
        return unique
    
    def _ai_analyze_dependencies(self, dependencies: List[Dict[str, str]]) -> Dict[str, Any]:
        """Use AI to analyze dependencies for potential risks"""
        # In production, this would call watsonx AI
        # For now, return basic analysis
        
        risky_patterns = ['alpha', 'beta', 'rc', 'snapshot', '0.0.', '0.1.']
        outdated_threshold = 2  # Major versions behind
        
        analysis = {
            'total_analyzed': len(dependencies),
            'potentially_risky': [],
            'outdated': [],
            'deprecated': []
        }
        
        for dep in dependencies:
            # Check for pre-release versions
            if any(pattern in dep['version'].lower() for pattern in risky_patterns):
                analysis['potentially_risky'].append({
                    'name': dep['name'],
                    'version': dep['version'],
                    'reason': 'Pre-release or unstable version'
                })
        
        return analysis
    
    def _identify_risk_flags(self, dependencies: List[Dict[str, str]]) -> List[str]:
        """Identify risk flags in dependencies"""
        flags = []
        
        # Check for known risky packages
        risky_packages = ['lodash', 'moment', 'request']  # Example list
        
        for dep in dependencies:
            if any(risky in dep['name'].lower() for risky in risky_packages):
                flags.append(f"Known risky package: {dep['name']}")
        
        return flags

# Made with Bob
