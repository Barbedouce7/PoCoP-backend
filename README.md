# PoCoP backend API

## Overview

The **PoCoP Backend API** is the server-side component of the PoCoP platform, hosted at [pocop.indigodao.org](https://pocop.indigodao.org).
Quicklinks : [indigodao.org](https://indigodao.org)

## Features
- cardano wallet auth
- anybody can submit content if connected
- specific stakekeys can moderate ( .env file )
- moderators can vote, categorize content and export the results

## Prerequisites

Node, Yarn, database (mongoDB or mariaDB)

## QuickStart

```bash
   git clone https://github.com/Barbedouce7/PoCoP-backend.git
   cd PoCoP-backend
   cp .env.example .env
   nano .env
   yarn install
```

## Environment Variables

The API relies on a .env file for sensitive configuration. Refer to .env.example for the required variables. 



