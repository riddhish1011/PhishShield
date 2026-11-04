# PhishShield (Vercel version)

Structure:

    phishshield-vercel/
      api/scan.py        <- Python serverless function (the scanner)
      public/index.html  <- the website (green/black 3D theme)
      vercel.json

## Deploy (GitHub + Vercel dashboard)

1. Push this folder to a new GitHub repo.
2. vercel.com -> Add New -> Project -> import the repo.
3. Framework Preset: **Other**. Leave Build Command empty. Deploy.
4. (Optional) Settings -> Environment Variables, then Redeploy:
   - GOOGLE_SAFE_BROWSING_API_KEY = your key
   - TRUSTED_HOSTS = your-project.vercel.app, your-custom-domain.com

## Deploy (CLI)

    npm i -g vercel
    vercel login
    vercel          # preview
    vercel --prod   # production

## Run locally

    vercel dev
