import os
import json
import requests
import yaml
from datetime import datetime
from pathlib import Path
import shutil

# Configuration
MITRE_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DATA_DIR = Path("data")
INDEX_FILE = Path("README.md")

def fetch_mitre_data():
    print(f"Fetching data from {MITRE_JSON_URL}...")
    response = requests.get(MITRE_JSON_URL)
    response.raise_for_status()
    return response.json()

def get_entity_type(entity):
    # MITRE CTI schema often uses 'type' field
    return entity.get('type', 'unknown').lower()

def format_relations(entity):
    relations = []
    # Common relation keys in MITRE CTI
    # Note: MITRE CTI relationships are often in a separate 'relationship' object,
    # but some entities embed references. We'll handle common patterns.
    relation_keys = ['related-resources', 'external_references', 'mitigations', 'techniques', 'software', 'groups']
    
    for key in relation_keys:
        if key in entity:
            for item in entity[key]:
                if isinstance(item, dict):
                    if 'external_id' in item:
                        relations.append(item['external_id'])
                    elif 'id' in item:
                        relations.append(item['id'])
                elif isinstance(item, str):
                    relations.append(item)
    return list(set(relations))

def write_entity_md(entity, base_dir):
    # MITRE CTI uses 'external_id' for things like T1059
    entity_id = entity.get('external_id') or entity.get('id')
    if not entity_id:
        return None

    entity_type = get_entity_type(entity)
    entity_name = entity.get('name', 'Unknown')
    
    # Create directory: data/{type}/{id}/
    entity_dir = base_dir / entity_type / entity_id
    entity_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = entity_dir / f"{entity_id}.md"
    
    # Prepare Metadata
    relations = format_relations(entity)
    metadata = {
        "id": entity_id,
        "name": entity_name,
        "type": entity_type,
        "relations": relations,
        "last_updated": datetime.now().isoformat()
    }
    
    # Prepare Content
    description = entity.get('description', 'No description provided.')
    
    # Build Markdown
    md_content = "---\n"
    md_content += yaml.dump(metadata, sort_keys=False).strip()
    md_content += "\n---\n\n"
    md_content += f"# {entity_name} ({entity_id})\n\n"
    md_content += f"## Description\n{description}\n\n"
    
    if relations:
        md_content += "## Relations\n"
        for rel_id in relations:
            md_content += f"- [[{rel_id}]]\n"
        md_content += "\n"

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    
    return entity_id, entity_name, entity_type

def update_index(all_entities):
    print(f"Updating index file {INDEX_FILE}...")
    lines = ["# MITRE ATT&CK Index\n", f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "## Summary Table\n", "| ID | Name | Type | Link |\n", "| --- | --- | --- | --- |\n"]
    
    # Sort entities by type then ID for a clean table
    all_entities.sort(key=lambda x: (x[2], x[0]))
    
    for eid, name, etype in all_entities:
        # Link format: data/type/id/id.md
        link = f"data/{etype}/{eid}/{eid}.md"
        lines.append(f"| {eid} | {name} | {etype} | [View]({link}) |")
    
    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def main():
    try:
        data = fetch_mitre_data()
    except Exception as e:
        print(f"Failed to fetch data: {e}")
        return

    objects = data.get('objects', [])
    if not objects:
        print("No objects found in JSON.")
        return

    # Clear existing data directory to ensure clean sync
    if DATA_DIR.exists():
        print("Cleaning old data directory...")
        shutil.rmtree(DATA_DIR)
    DATA_DIR.mkdir()

    processed_entities = []
    print(f"Processing {len(objects)} objects...")
    
    for obj in objects:
        try:
            result = write_entity_md(obj, DATA_DIR)
            if result:
                processed_entities.append(result)
        except Exception as e:
            # Silently skip errors for individual objects to keep the sync moving
            continue

    update_index(processed_entities)
    print(f"Sync complete. Processed {len(processed_entities)} entities.")

if __name__ == "__main__":
    main()