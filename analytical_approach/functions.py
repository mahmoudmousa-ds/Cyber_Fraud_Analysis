
# Import necessary libraries
import pandas as pd
import ipinfo
from user_agents import parse
import networkx as nx
import matplotlib.pyplot as plt
import time
import os
import hashlib
import re

from IPython.display import Image
# matplotlib.use("Agg")  # Non-interactive backend
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
#Function to extract information from ip like Country, City, Region, time zone and org usi




def get_ip_details(ip_address, handler):
    """Fetches details for a single IP address using ipinfo."""
    if not ip_address or pd.isna(ip_address):
        return {
            'country': None, 
            'city': None, 
            'region': None, 
            'timezone': None, 
            'org': None}
    try:
        # Ensure ip_address is a string
        ip_address = str(ip_address).strip()
        if not ip_address: # Handle empty strings after stripping
             return { 'country': None, 'city': None, 'region': None, 'timezone': None, 'org': None}
        details = handler.getDetails(ip_address)
        # Extract relevant fields, handling potential missing keys
        return {
            'country': getattr(details, 'country_name', None),
            'city': getattr(details, 'city', None),
            'region': getattr(details, 'region', None),
            'timezone': getattr(details, 'timezone', None),
            'org': getattr(details, 'org', None) # Organization/ISP can be useful
        }
    except Exception as e:
        print(f"Error fetching details for IP {ip_address}: {e}")
        # Return None for all fields on error
        return { 'country': None, 'city': None, 'region': None, 'timezone': None, 'org': None}
    


def split_name_version(text):
    """Helper to split text into name and version."""
    if pd.isna(text):
        return None, None
    match = re.match(r'^([^\d]+)\s*([\d\.]+.*)?$', text.strip())
    if match:
        name = match.group(1).strip()
        version = match.group(2).strip() if match.group(2) else None
        return name, version
    else:
        return text.strip(), None

def parse_user_agent(browser_string, os_string):
    """Parses browser and OS strings with manual fallback if needed."""

    # If both missing
    if pd.isna(browser_string) and pd.isna(os_string):
        return {
            'ua_browser': None,
            'ua_browser_version': None,
            'ua_os': None,
            'ua_os_version': None,
            'ua_is_mobile': None,
            'ua_is_pc': None
        }

    # Build fake UA string
    ua_string = f"{browser_string} ({os_string})"
    
    try:
        ua = parse(ua_string)

        # Use manual splitting instead of relying on user_agents output
        browser_family, browser_version = split_name_version(browser_string)
        os_family, os_version = split_name_version(os_string)

        is_mobile = ua.is_mobile
        is_pc = ua.is_pc

        # If user_agents can't detect device type → manually infer
        if is_mobile is False and is_pc is False:
            os_family_lower = (str(os_family) or "").lower()
            if any(keyword in os_family_lower for keyword in ['windows', 'mac', 'linux', 'ubuntu']):
                is_mobile = False
                is_pc = True
            elif any(keyword in os_family_lower for keyword in ['android', 'ios', 'iphone', 'ipad']):
                is_mobile = True
                is_pc = False
            else:
                is_mobile = None
                is_pc = None

        return {
            'ua_browser': browser_family,
            'ua_browser_version': browser_version,
            'ua_os': os_family,
            'ua_os_version': os_version,
            'ua_is_mobile': is_mobile,
            'ua_is_pc': is_pc
        }

    except Exception as e:
        print(f"Error parsing UA string '{ua_string}': {e}")

        # Manual fallback
        browser_family, browser_version = split_name_version(browser_string)
        os_family, os_version = split_name_version(os_string)

        is_mobile = None
        is_pc = None
        if os_family:
            os_family_lower = os_family.lower()
            if any(keyword in os_family_lower for keyword in ['windows', 'mac', 'linux', 'ubuntu']):
                is_mobile = False
                is_pc = True
            elif any(keyword in os_family_lower for keyword in ['android', 'ios', 'iphone', 'ipad']):
                is_mobile = True
                is_pc = False

        return {
            'ua_browser': browser_family,
            'ua_browser_version': browser_version,
            'ua_os': os_family,
            'ua_os_version': os_version,
            'ua_is_mobile': is_mobile,
            'ua_is_pc': is_pc
        }


# --- Extract Linking Attributes ---
def extract_compromised_attributes(compromised_device_rows, compromised_identity_rows, 
                                 COMPROMISED_DEVICE_ID, COMPROMISED_IDENTITY):
    """
    Extract all attributes (fingerprints, IPs, identities, devices) linked to compromised entities.
    Returns sets of compromised attributes and prints summary statistics.
    """
    compromised_fingerprints = set()
    compromised_ips = set()
    compromised_identities = set()
    compromised_devices = set()

    # Process compromised devices
    if not compromised_device_rows.empty:
        # Handle device fingerprints
        valid_fingerprints = compromised_device_rows['device_fingerprint'].dropna().unique()
        compromised_fingerprints.update(fp for fp in valid_fingerprints if fp != '-')
        
        # Handle IPs (assuming 'ips' column contains lists)
        for ip_list in compromised_device_rows['ips'].dropna():
            compromised_ips.update(ip for ip in ip_list if ip != '-')
            
        # Handle identities
        valid_identities = compromised_device_rows['identity'].dropna().unique()
        compromised_identities.update(id_ for id_ in valid_identities if id_ != '-')
        
        # Add the main compromised device
        if COMPROMISED_DEVICE_ID and COMPROMISED_DEVICE_ID != '-':
            compromised_devices.add(COMPROMISED_DEVICE_ID)

    # Process compromised identities
    if not compromised_identity_rows.empty:
        # Handle device fingerprints
        valid_fingerprints = compromised_identity_rows['device_fingerprint'].dropna().unique()
        compromised_fingerprints.update(fp for fp in valid_fingerprints if fp != '-')
        
        # Handle IPs
        for ip_list in compromised_identity_rows['ips'].dropna():
            compromised_ips.update(ip for ip in ip_list if ip != '-')
            
        # Handle device IDs
        valid_devices = compromised_identity_rows['device_id'].dropna().unique()
        compromised_devices.update(dev for dev in valid_devices if dev != '-')
        
        # Add the main compromised identity
        if COMPROMISED_IDENTITY and COMPROMISED_IDENTITY != '-':
            compromised_identities.add(COMPROMISED_IDENTITY)

    # Generate summary statistics
    summary = {
        'identities': len(compromised_identities),
        'devices': len(compromised_devices),
        'fingerprints': len(compromised_fingerprints),
        'ips': len(compromised_ips)
    }

    print("\nAttributes linked to compromised entities:")
    print(f"- {summary['identities']} unique identities: {sorted(compromised_identities)[:5]}{'...' if len(compromised_identities) > 5 else ''}")
    print(f"- {summary['devices']} unique device IDs: {sorted(compromised_devices)[:5]}{'...' if len(compromised_devices) > 5 else ''}")
    print(f"- {summary['fingerprints']} unique fingerprints: {sorted(compromised_fingerprints)[:5]}{'...' if len(compromised_fingerprints) > 5 else ''}")
    print(f"- {summary['ips']} unique IP addresses: {sorted(compromised_ips)[:5]}{'...' if len(compromised_ips) > 5 else ''}")

    return {
        'fingerprints': compromised_fingerprints,
        'ips': compromised_ips,
        'identities': compromised_identities,
        'devices': compromised_devices,
        'summary': summary
    }


# --- Find Connections ---
def find_connections(new_df, compromised_data, COMPROMISED_DEVICE_ID, COMPROMISED_IDENTITY):
    """
    Identify all records connected to compromised entities through various relationships.
    Returns DataFrame with connected records and their connection reasons.
    """
    print("\nSearching for connections...")
    
    # Initialize collection of connected indices
    connected_indices = set()
    connection_dfs = []
    
    # 1. Direct links (the compromised entities themselves)
    direct_mask = ((new_df['device_id'] == COMPROMISED_DEVICE_ID) | 
                  (new_df['identity'] == COMPROMISED_IDENTITY))
    direct_links = new_df[direct_mask].copy()
    if not direct_links.empty:
        direct_links['connection_type'] = 'direct'
        direct_links['connection_detail'] = 'Directly Compromised'
        connection_dfs.append(direct_links)
        connected_indices.update(direct_links.index)
    
    # 2. Shared Device Fingerprints
    if compromised_data.get('fingerprints'):
        fp_mask = (new_df['device_fingerprint'].isin(compromised_data['fingerprints']) & 
                  ~new_df.index.isin(connected_indices))
        shared_fp_links = new_df[fp_mask].copy()
        if not shared_fp_links.empty:
            shared_fp_links['connection_type'] = 'fingerprint'
            shared_fp_links['connection_detail'] = 'Shared Fingerprint'
            connection_dfs.append(shared_fp_links)
            connected_indices.update(shared_fp_links.index)
    
    # 3. Shared IP Addresses (optimized vectorized approach)
    if compromised_data.get('ips'):
        ip_records = []
        for idx, row in new_df[~new_df.index.isin(connected_indices)].iterrows():
            if isinstance(row.get('ips'), list):  # Check if ips exists and is a list
                for ip in row['ips']:
                    ip_records.append({'index': idx, 'ip': ip})
        
        if ip_records:
            ip_df = pd.DataFrame(ip_records)
            shared_ips = ip_df[ip_df['ip'].isin(compromised_data['ips'])]
            
            if not shared_ips.empty:
                shared_ip_indices = shared_ips['index'].unique()
                shared_ip_links = new_df.loc[shared_ip_indices].copy()
                
                ip_mapping = shared_ips.groupby('index')['ip'].apply(list)
                shared_ip_links['shared_ips'] = shared_ip_links.index.map(ip_mapping)
                
                shared_ip_links['connection_type'] = 'ip'
                shared_ip_links['connection_detail'] = shared_ip_links['shared_ips'].apply(
                    lambda ips: f"Shared IP ({', '.join(map(str, ips[:3]))}{'...' if len(ips) > 3 else ''}"
                )
                connection_dfs.append(shared_ip_links)
                connected_indices.update(shared_ip_links.index)
    
    # 4. Shared Identity
    if compromised_data.get('identities'):
        identity_mask = (new_df['identity'].isin(compromised_data['identities']) & 
                        ~new_df.index.isin(connected_indices))
        shared_identity_links = new_df[identity_mask].copy()
        if not shared_identity_links.empty:
            shared_identity_links['connection_type'] = 'identity'
            shared_identity_links['connection_detail'] = 'Shared Identity'
            connection_dfs.append(shared_identity_links)
            connected_indices.update(shared_identity_links.index)
    
    # 5. Shared Device ID
    if compromised_data.get('devices'):
        device_mask = (new_df['device_id'].isin(compromised_data['devices']) & 
                      ~new_df.index.isin(connected_indices))
        shared_device_links = new_df[device_mask].copy()
        if not shared_device_links.empty:
            shared_device_links['connection_type'] = 'device'
            shared_device_links['connection_detail'] = 'Shared Device ID'
            connection_dfs.append(shared_device_links)
            connected_indices.update(shared_device_links.index)
    
    # --- Combine Results with Null Checks ---
    all_connections = pd.DataFrame()  # Initialize empty DataFrame
    
    if connection_dfs:  # Only concatenate if we have DataFrames to combine
        try:
            all_connections = pd.concat(connection_dfs, ignore_index=True)
            
            # Add risk scoring if we have connections
            if not all_connections.empty:
                risk_scores = {
                    'direct': 100,
                    'device': 80,
                    'identity': 70,
                    'fingerprint': 60,
                    'ip': 50
                }
                all_connections['risk_score'] = all_connections['connection_type'].map(risk_scores)
                
                # Safe sorting
                sort_columns = ['risk_score']
                ascending = [False]
                
                if 'timestamp' in all_connections.columns:
                    sort_columns.append('timestamp')
                    ascending.append(True)
                
                all_connections = all_connections.sort_values(sort_columns, ascending=ascending)
        except Exception as e:
            print(f"Error combining connections: {str(e)}")
            return pd.DataFrame()  # Return empty DataFrame on error
    
    return all_connections
    # # 6. Multi-country devices (NEW)
    # exploded_df = new_df.explode('country')
    # country_counts = exploded_df.groupby('device_id')['country'].nunique()
    # multi_country_devices = country_counts[country_counts > 1].index
    # multi_country_links = new_df[(new_df['device_id'].isin(multi_country_devices)) &
    #                              (~new_df.index.isin(connected_indices))].copy()
    # if not multi_country_links.empty:
    #     multi_country_links['connection_type'] = 'multi_country'
    #     multi_country_links['connection_detail'] = 'Device used in multiple countries'
    #     connection_dfs.append(multi_country_links)
    #     connected_indices.update(multi_country_links.index)
    
    # # Combine Results with Null Checks
    # all_connections = pd.DataFrame()
    # if connection_dfs:
    #     try:
    #         all_connections = pd.concat(connection_dfs, ignore_index=True)
            
    #         # Add risk scoring
    #         if not all_connections.empty:
    #             risk_scores = {
    #                 'direct': 100,
    #                 'device': 80,
    #                 'identity': 70,
    #                 'fingerprint': 60,
    #                 'ip': 50,
    #                 'multi_country': 40  # Add score for multi-country
    #             }
    #             all_connections['risk_score'] = all_connections['connection_type'].map(risk_scores)
                
    #             sort_columns = ['risk_score']
    #             ascending = [False]
                
    #             if 'timestamp' in all_connections.columns:
    #                 sort_columns.append('timestamp')
    #                 ascending.append(True)
                
    #             all_connections = all_connections.sort_values(sort_columns, ascending=ascending)
    #     except Exception as e:
    #         print(f"Error combining connections: {str(e)}")
    #         return pd.DataFrame()
    
    # return all_connections



def create_basic_network_graph(df_associated, output_image_path="graphs/compromised_accounts_network.png"):
    """
    Creates and visualizes a basic network graph of associated entities.
    
    Args:
        df_associated (pd.DataFrame): DataFrame containing connection data
        output_image_path (str): Path to save the output image
        
    Returns:
        networkx.Graph: The created graph object
    """
    print(f"Loaded {len(df_associated)} associated records.")
    
    # Create a graph
    G = nx.Graph()
    node_types = {}

    # Add nodes and edges from the associated records
    for index, row in df_associated.iterrows():
        identity = str(row["identity"])
        device_id = str(row["device_id"])
        fingerprint = str(row["device_fingerprint"])
        ip = str(row["ip"])

        # Add nodes with type attribute
        if identity != "-":
            if identity not in G:
                G.add_node(identity, type="identity")
                node_types[identity] = "identity"
            
            # Add target nodes if they don't exist yet
            for node, node_type in [(device_id, "device_id"), 
                                  (fingerprint, "fingerprint"), 
                                  (ip, "ip")]:
                if node not in G:
                    G.add_node(node, type=node_type)
                    node_types[node] = node_type
                G.add_edge(identity, node)

        # Ensure nodes exist before adding edges between them
        for node in [device_id, fingerprint, ip]:
            if node not in G:
                G.add_node(node, type="device_id" if node == device_id else 
                          "fingerprint" if node == fingerprint else "ip")
                node_types[node] = G.nodes[node]["type"]

        # Add edges representing connections within the record
        if device_id != "-" and fingerprint != "-":
            G.add_edge(device_id, fingerprint)
        if device_id != "-" and ip != "-":
            G.add_edge(device_id, ip)

    print(f"Graph created with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.")

    # Visualization
    plt.figure(figsize=(20, 20))
    
    # Define colors and sizes based on node type
    color_map = []
    size_map = []
    node_labels = {}
    for node in G:
        node_type = node_types.get(node, "unknown")
        if node_type == "identity":
            color_map.append("red")
            size_map.append(1200)
            node_labels[node] = node[:8]
        elif node_type == "device_id":
            color_map.append("blue")
            size_map.append(600)
            node_labels[node] = "Dev..." + node[-4:]
        elif node_type == "fingerprint":
            color_map.append("green")
            size_map.append(400)
            node_labels[node] = "FP..." + node[-4:]
        elif node_type == "ip":
            color_map.append("orange")
            size_map.append(250)
            node_labels[node] = node
        else:
            color_map.append("grey")
            size_map.append(100)
            node_labels[node] = str(node)[:10]

    pos = nx.spring_layout(G, k=0.6, iterations=60, seed=42)
    nx.draw(G, pos, node_color=color_map, node_size=size_map, 
            labels=node_labels, with_labels=True, font_size=9, 
            alpha=0.8, edge_color="#cccccc", width=0.5)

    # Create legend
    legend_elements = [
        Line2D([0], [0], marker="o", color="w", label="Identity (red)", 
               markerfacecolor="red", markersize=12),
        Line2D([0], [0], marker="o", color="w", label="Device ID (blue)", 
               markerfacecolor="blue", markersize=10),
        Line2D([0], [0], marker="o", color="w", label="Fingerprint (green)", 
               markerfacecolor="green", markersize=8),
        Line2D([0], [0], marker="o", color="w", label="IP Address (orange)", 
               markerfacecolor="orange", markersize=6)
    ]
    plt.legend(handles=legend_elements, loc="upper right", title="Node Types")
    plt.title("Network Graph of Entities Associated with Compromised Account/Device", size=22)
    plt.axis("off")

    plt.savefig(output_image_path, bbox_inches="tight")
    print(f"Connection graph saved to {output_image_path}")
    
    return G

def create_enhanced_network_graph(df_associated, output_image_path="data/enhanced_compromised_accounts_network.png"):
    """
    Creates and visualizes an enhanced network graph with better styling.
    
    Args:
        df_associated (pd.DataFrame): DataFrame containing connection data
        output_image_path (str): Path to save the output image
        
    Returns:
        networkx.Graph: The created graph object
    """
    print(f"Loaded {len(df_associated)} associated records.")

    G = nx.Graph()
    node_attrs = {}

    for _, row in df_associated.iterrows():
        identity = str(row["identity"])
        device_id = str(row["device_id"])
        fingerprint = str(row["device_fingerprint"])
        ip = str(row["ip"])

        # Add nodes with attributes
        if identity != "-":
            if identity not in G:
                G.add_node(identity, type="identity", label=f"User\n{identity[:6]}...")
                node_attrs[identity] = {"color": "red", "size": 1200}
            
            # Add connections only if they exist
            for node, node_type in [(device_id, "device_id"), 
                                  (fingerprint, "fingerprint"), 
                                  (ip, "ip")]:
                if node != "-":
                    if node not in G:
                        color = {"device_id": "blue", "fingerprint": "green", "ip": "orange"}[node_type]
                        G.add_node(node, type=node_type, label=node[-6:])
                        node_attrs[node] = {"color": color, "size": 600 if node_type == "device_id" else 400}
                    G.add_edge(identity, node)

    print(f"Graph created with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.")

    # Visualization
    plt.figure(figsize=(24, 18))
    
    # Extract attributes for visualization
    node_colors = [node_attrs[n]["color"] for n in G.nodes()]
    node_sizes = [node_attrs[n]["size"] for n in G.nodes()]
    labels = {n: G.nodes[n].get("label", "") for n in G.nodes()}

    pos = nx.spring_layout(G, k=0.15, iterations=100, seed=42)

    # Draw with better styling
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9)
    nx.draw_networkx_edges(G, pos, edge_color="gray", width=0.3, alpha=0.5)
    nx.draw_networkx_labels(G, pos, labels, font_size=8, font_weight="bold")

    # Enhanced legend
    legend_elements = [
        plt.Line2D([0], [0], marker='o', color='w', label='User Accounts',
                  markerfacecolor='red', markersize=15),
        plt.Line2D([0], [0], marker='o', color='w', label='Device IDs',
                  markerfacecolor='blue', markersize=12),
        plt.Line2D([0], [0], marker='o', color='w', label='Fingerprints',
                  markerfacecolor='green', markersize=10),
        plt.Line2D([0], [0], marker='o', color='w', label='IP Addresses',
                  markerfacecolor='orange', markersize=8)
    ]

    plt.legend(handles=legend_elements, loc='upper right', title="Node Types")
    plt.title("Compromised Account Connection Network\n(Red nodes indicate user identities)", fontsize=18, pad=20)
    plt.axis('off')

    plt.savefig(output_image_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Network visualization saved to {output_image_path}")
    
    return G

import plotly.graph_objects as go
import networkx as nx

def create_interactive_network(df_associated, output_html="interactive_network.html"):
    """
    Creates an interactive network graph from associated account data.
    
    Args:
        df_associated (pd.DataFrame): DataFrame containing connection data
        output_html (str): Path to save the interactive HTML file
        
    Returns:
        plotly.graph_objects.Figure: The interactive Plotly figure
    """
    # Create the graph
    G = nx.Graph()
    node_attrs = {}

    for _, row in df_associated.iterrows():
        identity = str(row["identity"])
        device_id = str(row["device_id"])
        fingerprint = str(row["device_fingerprint"])
        ip = str(row["ip"])
        bank_id = str(row.get("bank", row.get("bank_id", "N/A")))
        country = str(row.get("country", "N/A"))

        if identity != "-":
            if identity not in G:
                G.add_node(identity, type="identity", bank=bank_id, country=country)
                node_attrs[identity] = {"color": "red", "size": 30}
            
            for node, node_type in [(device_id, "device_id"), 
                                  (fingerprint, "fingerprint"), 
                                  (ip, "ip")]:
                if node != "-":
                    if node not in G:
                        color = {"device_id": "blue", "fingerprint": "green", "ip": "orange"}[node_type]
                        G.add_node(node, type=node_type, bank=bank_id, country=country)
                        node_attrs[node] = {
                            "color": color, 
                            "size": 20 if node_type == "device_id" else 15
                        }
                    G.add_edge(identity, node)

    print(f"Graph created with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.")

    # Get positions using spring layout
    pos = nx.spring_layout(G, k=0.15, iterations=100, seed=42)

    # Prepare edge traces
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )

    # Prepare node traces
    node_x, node_y, node_hovertext = [], [], []
    node_size, node_color = [], []
    
    for node in G.nodes():
        node_x.append(pos[node][0])
        node_y.append(pos[node][1])
        node_info = (
            f"<b>Type:</b> {G.nodes[node]['type']}<br>"
            f"<b>Node ID:</b> {node}<br>"
            f"<b>Bank ID:</b> {G.nodes[node].get('bank')}<br>"
            f"<b>Country:</b> {G.nodes[node].get('country', 'N/A')}"
        )
        node_hovertext.append(node_info)
        node_size.append(node_attrs[node]["size"])
        node_color.append(node_attrs[node]["color"])

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        marker=dict(
            size=node_size,
            color=node_color,
            line=dict(width=1, color='black'),
            opacity=0.9
        ),
        hoverinfo='text',
        hovertext=node_hovertext
    )

    # Create figure
    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title='<b>Compromised Accounts Network</b><br><i>Hover for details - Red nodes are user identities</i>',
            titlefont_size=16,
            showlegend=False,
            hovermode='closest',
            margin=dict(b=100, l=100, r=20, t=60),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=800,
            paper_bgcolor='white',
            plot_bgcolor='white'
        )
    )

    # Add compact legend
    legend_items = [('Users', 'red'), ('Devices', 'blue'), 
                   ('Fingerprints', 'green'), ('IPs', 'orange')]
    
    legend_text = "<b>LEGEND</b><br>" + "<br>".join(
        [f"<span style='color:{color}'>●</span> {label}" 
         for label, color in legend_items]
    )

    fig.add_annotation(
        x=0.02, y=0.05,
        xref="paper", yref="paper",
        text=legend_text,
        showarrow=False,
        font=dict(size=12),
        align="left",
        bordercolor="#cccccc",
        borderwidth=1,
        borderpad=4,
        bgcolor="white",
        opacity=0.8
    )

    # Save and return
    fig.write_html(output_html)
    print(f"Interactive network saved to {output_html}")
    return fig
