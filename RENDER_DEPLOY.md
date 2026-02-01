# Render Deployment Guide for CertiTrust

## Quick Deploy (Blueprint)

1. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Add Render deployment"
   git push origin main
   ```

2. **Connect to Render**
   - Go to [render.com/blueprints](https://render.com/blueprints)
   - Click "New Blueprint Instance"
   - Connect your GitHub repo
   - Render auto-detects `render.yaml`

3. **Set Environment Variables**
   In Render Dashboard → Environment:
   ```
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_KEY=your-anon-key
   SUPABASE_SERVICE_KEY=your-service-key
   ```

## Manual Deploy (Alternative)

### Backend Service
1. New → Web Service → Connect repo
2. Settings:
   - **Root Directory**: `backend`
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT`

### Frontend Service
1. New → Web Service → Connect repo
2. Settings:
   - **Root Directory**: `web`
   - **Runtime**: Node
   - **Build Command**: `npm ci && npm run build`
   - **Start Command**: `npm start`

## Environment Variables

| Variable | Service | Description |
|----------|---------|-------------|
| `SUPABASE_URL` | Backend | Supabase project URL |
| `SUPABASE_KEY` | Backend | Supabase anon key |
| `SUPABASE_SERVICE_KEY` | Backend | Supabase service role key |
| `NEXT_PUBLIC_API_URL` | Frontend | Backend URL (auto-linked) |
| `FRONTEND_URL` | Backend | Frontend URL (auto-linked) |

## URLs After Deploy

- **API**: `https://certitrust-api.onrender.com`
- **Web**: `https://certitrust-web.onrender.com`

## Notes

- Free tier: Services spin down after 15 min inactivity
- Starter plan ($7/mo): Always on, faster cold starts
- First deploy takes ~5-10 minutes
