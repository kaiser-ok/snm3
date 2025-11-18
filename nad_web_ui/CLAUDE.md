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
   - Time range selector (15/30/60/120 minutes)
   - Execute anomaly detection
   - Display results grouped by 5-minute time buckets
   - Expandable IP details with device type icons

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
1. User selects time range in Dashboard
2. Frontend calls `POST /api/detection/run` with `{minutes: 60}`
3. `detector_service.py` queries Elasticsearch for pre-stored anomaly results
4. Results grouped into 5-minute buckets with device classification
5. Frontend displays buckets as expandable cards

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

**Elasticsearch Queries:**
- All services query the `network-flow-*` index pattern
- Detector service queries pre-computed anomaly results (not real-time detection)
- Analysis service performs aggregations for IP statistics

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

