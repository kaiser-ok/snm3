# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.
please think about my prompt in CLI, don't just trust my logic, sometimes is wrong, you need to ask me if necessar.
## Project Overview

NAD Web UI (網路異常檢測系統) is a full-stack web application for network anomaly detection. It consists of a Flask backend API and a Vue.js 3 frontend, providing real-time network traffic analysis using machine learning (Isolation Forest algorithm).

**Key Components:**
- **Backend:** Flask REST API that interfaces with Elasticsearch and the NAD (Network Anomaly Detection) Python module located at `/home/kaisermac/snm_flow/nad`
- **Frontend:** Vue 3 + Vite SPA with Element Plus UI components
- **Data Source:** Elasticsearch 7.17.x storing network flow data
- **ML Model:** Isolation Forest for anomaly detection, trained on historical network traffic patterns

## Development Commands

### Backend (Flask)

```bash
# Start development server
cd /home/kaisermac/nad_web_ui/backend
python3 app.py
# Runs on http://0.0.0.0:5000

# Alternative: Use startup script
./start.sh

# Test APIs
./test_api.sh

# Install dependencies
pip install -r requirements.txt

# Production deployment with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 300 app:app
```

### Frontend (Vue.js)

```bash
# Start development server
cd /home/kaisermac/nad_web_ui/frontend
npm run dev
# Runs on http://0.0.0.0:5173

# Install dependencies
npm install

# Production build
npm run build
# Output to dist/ directory

# Preview production build
npm run preview
```

**Important:** The frontend development server proxies all `/api/*` requests to `http://localhost:5000` (configured in `vite.config.js`).

## Architecture & Code Structure

### Backend Architecture (Flask)

**Three-Layer Architecture:**
1. **API Layer** (`backend/api/`): Flask Blueprints handling HTTP requests/responses
   - `detection.py`: Anomaly detection endpoints
   - `training.py`: Model training endpoints (includes SSE for real-time progress)
   - `analysis.py`: IP analysis endpoints

2. **Service Layer** (`backend/services/`): Business logic and NAD module integration
   - `detector_service.py`: Interfaces with `nad.ml.OptimizedIsolationForest`
   - `training_service.py`: Handles model training workflows
   - `analysis_service.py`: IP traffic analysis and statistics
   - `llm_service.py`: OpenAI integration for security threat analysis

3. **NAD Module Integration**: External Python module at `/home/kaisermac/snm_flow/nad`
   - Dynamically added to `sys.path` in service classes
   - Key classes: `OptimizedIsolationForest`, `AnomalyClassifier`, `DeviceClassifier`
   - Requires `NAD_BASE_PATH`, `NAD_CONFIG_PATH`, `NAD_MODELS_PATH` environment variables

**Configuration:**
- Environment variables loaded from `.env` (see `.env.example`)
- `config.py` defines `Config`, `DevelopmentConfig`, `ProductionConfig`
- CORS configured for `localhost:5173` and `localhost:3000`

**Job Management:**
- Detection and training tasks use UUID-based job IDs
- Jobs cached in-memory with `JOB_CACHE_TTL` (3600s default)
- Training progress streamed via Server-Sent Events (SSE)

### Frontend Architecture (Vue 3)

**Key Technologies:**
- **State Management:** Pinia stores (`stores/detection.js`, `stores/training.js`)
- **Routing:** Vue Router with 3 main routes (`router/index.js`)
- **UI Components:** Element Plus (buttons, cards, forms, tables, messages)
- **HTTP Client:** Axios (`services/api.js`)
- **Charts:** ECharts library (imported but not fully utilized yet)

**Pages (`frontend/src/views/`):**
1. **Dashboard.vue** (`/`):
   - Time range selector (15/30/60/120/180/360/720 minutes, default: 180)
   - Execute anomaly detection
   - Display results grouped by 3-minute time buckets
   - Expandable IP details with device type icons
   - Bar chart visualization (loads historical anomaly counts)
   - Pie chart for behavior feature distribution

2. **Training.vue** (`/training`):
   - Current model information display
   - Training parameter configuration (days, exclude_servers)
   - Real-time training progress bar (SSE connection)
   - Training history (feature available)

3. **IPAnalysis.vue** (`/analysis`):
   - IP search and analysis form
   - Statistics summary (total flows, bytes, destinations, ports)
   - Top destinations table
   - Device type classification

**State Management Pattern:**
- Pinia stores handle API calls and state
- Components call store actions (`detection.runDetection()`, `training.startTraining()`)
- Reactive state automatically updates UI

### Data Flow

```
Frontend (Vue) → Axios API Service → Vite Proxy → Flask Blueprint → Service Layer → NAD Module → Elasticsearch
                                                                                           ↓
                                                                                    Model Files (.pkl)
```

**Anomaly Detection Flow:**
1. User selects time range in Dashboard (default: 180 minutes / 3 hours)
2. Frontend calls `POST /api/detection/run` with `{minutes: 180}`
3. `detector_service.py` queries Elasticsearch for pre-stored anomaly results from `anomaly_detection-*`
4. Results are grouped into 3-minute time buckets with device classification
5. SRC/DST dual perspective anomalies are intelligently merged (see below)
6. Frontend displays buckets as expandable cards

**Dual Perspective Anomaly Merging (realtime_detection_dual.py):**
The system analyzes network traffic from both SRC (source) and DST (destination) perspectives:

1. **Separate Detection:**
   - SRC model: Detects anomalous outbound traffic patterns
   - DST model: Detects anomalous inbound traffic patterns

2. **Intelligent Merging:**
   - Groups anomalies by `(IP, normalized_time_bucket)` (±6 min tolerance)
   - Analyzes bidirectional traffic patterns using:
     * Flow count ratio (>80% similarity)
     * Target/source count matching
     * **Port pattern analysis** (top_dst_ports)
     * Service identification (SNMP, DNS, HTTP, etc.)

3. **Merge Rules:**
   - **Rule 1 (Scan Response):** Remove DST "Scan Response" if SRC is "Port/Network Scanning"
   - **Rule 2 (Bidirectional Service):** Merge if:
     * Flow ratio > 0.8 AND
     * Target count matches (unique_dsts == unique_srcs) AND
     * Both use same well-known port (161, 53, 80, 443, etc.)
     * Reclassify as "Normal Bidirectional Service"
   - **Default:** Preserve both records if patterns don't match (different services or real threats)

4. **Port Features Used:**
   - `top_dst_ports`: Top 5 most frequently used destination ports
   - `unique_dst_ports`: Total number of unique destination ports
   - Well-known port detection: {161, 162, 53, 80, 443, 22, 23, 25, 110, 143, 389, 636, 3306, 5432, 6379, 27017}
   - Service mapping: Automatically identifies SNMP, DNS, HTTP, SSH, MySQL, etc.

**Model Training Flow:**
1. User configures parameters in Training page
2. Frontend calls `POST /api/training/start`
3. `training_service.py` starts background training job
4. Frontend establishes SSE connection to `GET /api/training/status/{job_id}`
5. Progress updates streamed in real-time
6. Model saved to `NAD_MODELS_PATH` on completion

## Important Development Notes

### Backend Development

**NAD Module Integration:**
- The backend depends on the external NAD module at `/home/kaisermac/snm_flow/nad`
- Service classes add this path to `sys.path` dynamically
- Ensure `NAD_BASE_PATH` environment variable is correctly set
- Model files (.pkl) are stored in `NAD_MODELS_PATH` (default: `/home/kaisermac/snm_flow/nad/models`)

**Elasticsearch Indices:**
- `radar_flow_collector-*`: Raw NetFlow data (24-hour retention)
- `netflow_stats_3m_by_src`: 3-minute aggregated SRC perspective traffic statistics
- `netflow_stats_3m_by_dst`: 3-minute aggregated DST perspective traffic statistics
- `anomaly_detection-*`: Pre-computed anomaly detection results
- All services query these indices for different purposes

**Elasticsearch Transforms:**
- `netflow_agg_3m_by_src`: Aggregates raw NetFlow into 3-minute buckets (SRC perspective)
  - Delay: 90 seconds
  - Key features: flow_count, unique_dsts, unique_dst_ports, top_dst_ports, total_bytes
- `netflow_agg_3m_by_dst`: Aggregates raw NetFlow into 3-minute buckets (DST perspective)
  - Delay: 90 seconds
  - Key features: flow_count, unique_srcs, unique_dst_ports, top_dst_ports, total_bytes
- **Note:** DST transform may lag behind SRC by ~3 minutes due to processing differences

**Detector Service Queries:**
- Queries `anomaly_detection-*` for pre-computed results (not real-time detection)
- Results are grouped into 3-minute time buckets
- Analysis service performs aggregations for IP statistics from `netflow_stats_3m_by_*`

**Error Handling:**
- All API responses use standardized format: `{"status": "success|error", "data": {...}}`
- Services wrap operations in try/except and return error dictionaries
- Frontend displays errors using Element Plus `ElMessage.error()`

**SSE Implementation:**
- Training endpoint uses `Response(stream_with_context(...), mimetype='text/event-stream')`
- Events formatted as `data: {json}\n\n`
- Frontend uses native `EventSource` API

### Frontend Development

**Proxy Configuration:**
- Development requests to `/api/*` automatically proxy to backend
- In production, Nginx should handle this proxying
- No need to use full URLs in API service (`/api/detection/run`, not `http://localhost:5000/...`)

**Device Type Icons:**
- Defined in NAD module at `/home/kaisermac/snm_flow/nad/device_classifier.py`
- Mapping: Server Farm (🏭), Workstation (💻), IoT (🛠️), External (🌐)

**Component Patterns:**
- Use Element Plus components (`<el-button>`, `<el-card>`, `<el-table>`, etc.)
- Form validation with Element Plus rules
- Loading states managed with `loading` refs
- Error handling with `ElMessage` notifications

**Adding New Features:**
- Charts: Import ECharts in component, initialize with `echarts.init()`
- New pages: Add to `router/index.js` and create corresponding view
- New API calls: Add to `services/api.js` and create/update Pinia store

## Testing

**Backend:**
```bash
cd backend
./test_api.sh  # Tests all API endpoints
curl http://localhost:5000/api/health  # Health check
```

**Frontend:**
- No automated tests currently implemented
- Manual testing via browser developer tools
- Check browser console for errors and network tab for API calls

## Configuration Files

**Backend Environment (`.env`):**
- `ES_HOST`: Elasticsearch connection URL (default: `http://localhost:9200`)
- `NAD_BASE_PATH`: Path to NAD module (default: `/home/kaisermac/snm_flow`)
- `NAD_CONFIG_PATH`: NAD YAML config (default: `/home/kaisermac/snm_flow/nad/config.yaml`)
- `NAD_MODELS_PATH`: Model storage directory (default: `/home/kaisermac/snm_flow/nad/models`)
- `OPENAI_API_KEY`: Optional, enables LLM-based security analysis
- `BACKEND_PORT`: Flask port (default: 5000)

**Frontend Configuration:**
- `vite.config.js`: Proxy settings, build options
- `package.json`: Dependencies and scripts

## Deployment

**Backend Production:**
1. Use Gunicorn with 4 workers and 300s timeout
2. Create systemd service (`nad-web-backend.service`)
3. Bind to `127.0.0.1:5000` (not `0.0.0.0`)
4. Use Nginx as reverse proxy
5. See `backend/README.md` for detailed systemd configuration

**Frontend Production:**
1. Run `npm run build` to create `dist/` directory
2. Serve static files with Nginx
3. Configure Nginx to proxy `/api/` requests to backend
4. See `DEPLOYMENT_GUIDE.md` for Nginx configuration example

## Elasticsearch Transform Features

### 3-Minute Aggregation Fields

**SRC Perspective (`netflow_stats_3m_by_src`):**
```json
{
  "src_ip": "192.168.10.100",
  "time_bucket": "2025-11-23T10:24:00.000Z",
  "flow_count": 1234,
  "unique_dsts": 45,
  "unique_dst_ports": 230,
  "unique_src_ports": 890,
  "total_bytes": 5678900,
  "avg_bytes": 4603,
  "top_dst_ports": {
    "80": 500,
    "443": 400,
    "53": 200,
    "22": 100,
    "161": 34
  },
  "top_src_ports": {
    "49152": 100,
    "49153": 98,
    ...
  },
  "top_dst_port_concentration": 0.406,
  "dst_well_known_ratio": 0.85
}
```

**DST Perspective (`netflow_stats_3m_by_dst`):**
```json
{
  "dst_ip": "192.168.10.100",
  "time_bucket": "2025-11-23T10:24:00.000Z",
  "flow_count": 1200,
  "unique_srcs": 45,
  "unique_dst_ports": 5,
  "unique_src_ports": 800,
  "total_bytes": 5400000,
  "avg_bytes": 4500,
  "top_dst_ports": {
    "80": 600,
    "443": 400,
    "22": 150,
    "161": 40,
    "3306": 10
  },
  "top_src_ports": {...},
  "dst_well_known_ratio": 1.0
}
```

### Key Metrics Explained

**Port Features:**
- `top_dst_ports`: Top 5 destination ports with flow counts (critical for service identification)
- `unique_dst_ports`: Total unique destination ports (high = port scan, low = normal service)
- `top_dst_port_concentration`: Percentage of flows on the top port (high = focused service)
- `dst_well_known_ratio`: Percentage of flows to well-known ports (0-1024)

**Traffic Features:**
- `flow_count`: Total number of NetFlow records in this 3-minute bucket
- `unique_dsts/srcs`: Number of unique communication targets/sources
- `total_bytes`: Sum of all bytes transferred
- `avg_bytes`: Average bytes per flow (small = scan/probe, large = data transfer)

**How Port Features Enable Smart Detection:**

1. **Service Identification:**
   ```
   top_dst_ports: {161: 438} → SNMP service
   top_dst_ports: {53: 1000} → DNS service
   top_dst_ports: {80: 500, 443: 400} → Web server
   ```

2. **Port Scan Detection:**
   ```
   unique_dst_ports: 438 / flow_count: 442 = 99% dispersion
   → Scanning different ports on each connection
   ```

3. **Bidirectional Service Validation:**
   ```
   SRC: top_dst_ports: {161: 100} + flow_count: 100
   DST: top_dst_ports: {161: 98}  + flow_count: 98
   → Symmetric SNMP request-response pattern
   ```

## Common Issues

**Backend Cannot Import NAD Module:**
- Check `NAD_BASE_PATH` environment variable
- Verify `/home/kaisermac/snm_flow/nad` exists and is accessible
- Check file permissions

**Elasticsearch Connection Failed:**
- Verify Elasticsearch is running: `systemctl status elasticsearch`
- Test connection: `curl http://localhost:9200`
- Check `ES_HOST` in `.env`

**Frontend Cannot Connect to Backend:**
- Ensure backend is running on port 5000
- Check Vite proxy configuration in `vite.config.js`
- Verify no CORS errors in browser console

**Training Takes Too Long / Fails:**
- Reduce training days parameter (recommend 3-7 days)
- Check available memory and disk space
- Monitor backend logs: `tail -f logs/backend.log`

## Language

The codebase uses Traditional Chinese (繁體中文) for:
- UI labels and messages
- Comments and documentation
- API response messages

Code identifiers (variables, functions, classes) use English.

## Shell Tools Usage Guidelines
⚠️ **IMPORTANT**: Use the following specialized tools instead of traditional Unix commands: (Install if missing)
| Task Type | Must Use | Do Not Use |
|-----------|----------|------------|
| Find Files | `fd` | `find`, `ls -R` |
| Search Text | `rg` (ripgrep) | `grep`, `ag` |
| Analyze Code Structure | `ast-grep` | `grep`, `sed` |
| Interactive Selection | `fzf` | Manual filtering |
| Process JSON | `jq` | `python -m json.tool` |
| Process YAML/XML | `yq` | Manual parsing |

