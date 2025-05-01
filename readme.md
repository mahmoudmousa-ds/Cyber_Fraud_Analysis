# Analytical Report: Cross-Bank Fraud Connection Analysis

**Date:** 1st May 30, 2025  
**Prepared For:** Management  
**Subject:** Analysis of User and Device Data to Identify Fraudulent Connections  

---

## Objective  
![alt text](<network graph/basic_network.png>)
To identify user accounts associated with a known compromised device or identity, analyze the connections, and present clear, actionable insights.

---

## Summary of Approaches

We applied **two complementary approaches** to detect fraud:

---

### Approach 1: Analytical Network Analysis (Manual Investigation)

**Goal:** Identify all user accounts linked to the known compromised device or identity.

**What we did:**  
✅ Started with the compromised **Device ID** `91b12379-8098-457f-a2ad-a94d767797c2` and **Identity** `0007f265568f1abc1da791e852877df2047b3af9`  
✅ Mapped related connections using device fingerprints, IP addresses, and user identities  
✅ Built a **network graph** to visualize relationships

**Key findings:**  
- Identified **5 suspicious user identities**:
  - `00010fb5147e6ec14e287ca903cd427339893450`  
  - `00064120f0aa15e8c4197cf9f18a03a6e4bd35cb`  
  - `0007f265568f1abc1da791e852877df2047b3af9` (original compromised identity)  
  - `0009e8252e8ffcb665b34c3dea1baee477fde74e`  
  - `e7190874862efef8d3acd53baba84bc54f29d111`

- Found **143 connection records** tied to this fraud cluster  
- Noticed **13 device IDs** using IP addresses from different countries — flagged as *potentially suspicious*; however, this may be explained by **legitimate VPN use**  
- Created a **color-coded network graph**:
  - Red: User identities  
  - Blue: Device IDs  
  - Green: Device fingerprints  
  - Orange: IP addresses  
  - Edges: Relationships between entities

**Recommended actions:**  
- Investigate the **5 identified accounts**  
- Review the **13 device IDs with cross-country IPs** (consider possible VPN use)  
- Increase **security monitoring** and alert relevant teams

---

### Approach 2: Machine Learning Model (Automated Detection)

**Goal:** Use AI to predict other potentially fraudulent connections in the dataset

**What we did:**  
✅ Built a **machine learning model** trained on known fraud patterns  
✅ Added indicators like shared IPs or fingerprints with compromised records  
✅ Ran the model across the **full dataset**

**Key findings:**  
- Reviewed **1802 total connections**  
- Identified **89 potentially fraudulent connections** beyond the initial cluster  
- Achieved **99.45% accuracy** with **100% recall**  
- Provided a **prioritized list** for investigation

**Recommended actions:**  
- Focus on the **top suspicious connections** flagged by the model  
- Use insights to **improve monitoring rules**  
- Regularly **retrain the model** with updated data

---

## ✅ Final Recommendations

Combine both approaches for maximum coverage:
- Use **manual analysis** to understand the fraud network  
- Use **machine learning** to uncover hidden patterns

**Prioritized investigation:**  
- **5 high-risk user accounts**  
- **89 flagged connections** from the model  
- **13 device IDs with cross-country IPs** (keeping in mind possible VPN use)

---

## Technologies and Tools

- **Pandas:** Data manipulation and analysis  
- **Openpyxl:** Read `.xlsx` files  
- **IPinfo:** IP geolocation and enrichment  
- **User-Agents:** Browser and OS parsing  
- **NetworkX:** Network graph modeling  
- **Matplotlib:** Visual graph generation

---

## Conclusion

The combined analytical and machine learning approaches successfully identified high-risk users and expanded detection to uncover hidden fraud patterns. This dual strategy balances accuracy with broader detection, improving our ability to mitigate fraud risks effectively.

---

**End of Report**
