require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Buffer } = require("buffer");
const { COSESign1, COSEKey, BigNum, Label, Int } = require("@emurgo/cardano-message-signing-nodejs");
const { Ed25519Signature, RewardAddress, PublicKey, Address } = require("@emurgo/cardano-serialization-lib-nodejs");
const CardanoWasm = require('@emurgo/cardano-serialization-lib-nodejs');
var cardanoAddresses = require('cardano-addresses')
const crypto = require('crypto');
const cbor = require('cbor');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Sequelize, Op, DataTypes } = require('sequelize');

const db_username = process.env.db_username;
const db_password = process.env.db_password;
const sequelize = new Sequelize({
  dialect: 'mariadb',
  host: '127.0.0.1',
  username: db_username,
  password: db_password,
  database: 'pocop'
});
const Commits = require('./models/Commits')(sequelize, DataTypes);
const Vote = require('./models/Vote')(sequelize, DataTypes);

Vote.belongsTo(Commits, {
    foreignKey: 'link_id',
    targetKey: 'id'
});

Commits.hasMany(Vote, {
    foreignKey: 'link_id',
    sourceKey: 'id'
});

const CORS_ORIGIN = process.env.cors_origin.split(',');
const registeredUsers = process.env.registered_users.split(',');
const secret = process.env.secret;
const secret2 = process.env.secret2;

const app = express();
const PORT = process.env.PORT;
const corsOptions = {
    origin: CORS_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
};
app.use(cors(corsOptions));


app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
  res.send('Backend is running');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});








const authorization = (req, res, next) => {
  const tokenFromCookies = req.cookies.token;
  const authTokenFromCookies = req.cookies.authToken;
  const authHeader = req.headers['authorization'];
  const tokenFromHeader = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  const token = tokenFromCookies || tokenFromHeader;
  const modToken = authTokenFromCookies;
  //console.log(token);
  if (!token && !modToken) {
    return next();
  }

  if (token) {
    try {
      const data = jwt.verify(token, secret);
      req.user = data;
      req.isAuthenticated = true;
      return next();
    } catch {
      // continue to try with mod token
    }
  }
  if (modToken || (tokenFromHeader && !req.isAuthenticated)) {
    try {
      const tokenToVerify = modToken || tokenFromHeader;
      const data = jwt.verify(tokenToVerify, secret2);
      req.user = data;
      req.isAuthenticated = true;
      req.isModerator = true;
      return next();
    } catch {
      // if both auth fail, return wihout auth :
      if (!req.isAuthenticated) {
        return next();
      }
    }
  }
  return next();
};




const authorizationmodo = (req, res, next) => {
  const tokenFromCookies = req.cookies.authToken;
  const authHeader = req.headers['authorization'];
  const tokenFromHeader = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  const token = tokenFromCookies || tokenFromHeader;
  //console.log('Token presence check:', !!token);
  if (!token) {
    return res.status(401).json({ error: 'No authentication token provided' });
  }
  try {
    const data = jwt.verify(token, secret2);
    const sanitizedData = {...data};
    // Check if username is a WebAssembly object and handle it
    if (data.username && typeof data.username === 'object' && data.username.__wbg_ptr) {
      // Use stakeKey as username or a string representation of the pointer
      sanitizedData.username = data.stakeKey || `user_${data.username.__wbg_ptr}`;
    }
    req.modo = sanitizedData;
    req.isModerator = true;
    console.log('Moderator authenticated:', sanitizedData.username);
    return next();
  } catch (error) {
    console.error('JWT verification error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};




const checkAccess = (req, res, next) => {
  if (req.isAuthenticated || req.isModerator) {
    return next();
  }
  return res.sendStatus(403);
};

app.post("/login", authenticate);

app.get('/profil', [authorization, checkAccess], (req, res) => {
  res.send('Backend is running');
});

app.get('/moderation', [authorizationmodo, checkAccess], (req, res) => {
  res.send('Backend is running');
});


app.post('/delete_commit', authorizationmodo, async (req, res) => {
    const { commit_id } = req.body;
    if (!commit_id) {
        return res.status(400).json({ error: 'Commit ID is required' });
    }
    try {
        const commit = await Commits.findByPk(commit_id);
        if (!commit) {
            return res.status(404).json({ error: 'Commit not found' });
        }
        await Vote.destroy({ where: { link_id: commit_id } });
        await Commits.destroy({ where: { id: commit_id } });
        res.status(200).json({ message: 'Commit deleted successfully' });
    } catch (error) {
        console.error('Error deleting commit:', error);
        res.status(500).json({ error: 'An error occurred while deleting the commit' });
    }
});



app.post('/submit_vote', authorizationmodo, async (req, res) => {
    const { commit_id, wallet_id, vote_value } = req.body;
    const moderatorWallet = req.modo.username;

    if (!moderatorWallet) {
      return res.status(401).json({ error: 'No wallet address provided' });
    }

    if (!commit_id || !vote_value || isNaN(vote_value) || vote_value < 0 || vote_value > 10) {
        return res.status(400).json({ error: 'Invalid request: commit_id and vote_value (0-10) are required' });
    }

    try {
        const existingVote = await Vote.findOne({
            where: { link_id: commit_id, wallet_id: moderatorWallet }
        });

        if (existingVote) {
            existingVote.vote_value = vote_value;
            await existingVote.save();
            res.status(200).json({ message: 'Vote updated successfully' });
        } else {
            await Vote.create({
                link_id: commit_id,
                wallet_id: moderatorWallet,
                vote_value: vote_value
            });
            res.status(201).json({ message: 'Vote submitted successfully' });
        }
    } catch (error) {
        console.error('Error submitting vote:', error);
        res.status(500).json({ error: 'An error occurred while submitting the vote' });
    }
});

app.post('/submit_category', authorizationmodo, async (req, res) => {
    const { commit_id, category } = req.body;
    const moderatorWallet = req.modo.username;
    console.log('category submission!');
    console.log(moderatorWallet);
    
    if (!moderatorWallet) {
        return res.status(401).json({ error: 'No wallet address provided' });
    }

    // Validate input
    if (!commit_id || !category || typeof category !== 'string' || category.length > 42) {
        return res.status(400).json({ 
            error: 'Invalid request: commit_id and category (string, max 42 characters) are required' 
        });
    }

    try {
        // Find the commit
        const commit = await Commits.findOne({
            where: { id: commit_id }
        });

        if (!commit) {
            return res.status(404).json({ error: 'Commit not found' });
        }

        // Update the category
        commit.category = category;
        await commit.save();
        
        res.status(200).json({ 
            message: 'Category updated successfully',
            commit_id: commit_id,
            category: category 
        });

    } catch (error) {
        console.error('Error submitting category:', error);
        res.status(500).json({ error: 'An error occurred while submitting the category' });
    }
});


app.post('/submit_link', authorization, async (req, res) => {
    const { addr, link } = req.body;

    if (!link) {
        return res.status(400).json({ error: 'The "link" field cannot be empty.' });
    }

    try {
        // Check if link already exist in db
        const existingCommit = await Commits.findOne({ where: { wallet: addr, link: link } });

        if (existingCommit) {
            return res.status(409).json({ error: 'This link has already been submitted.' });
        }
        const category = link.includes('youtube.com') || link.includes('youtu.be') ? 'youtube' : 'others';

        // check if more than X submit this month from the submitter
        const startOfMonth = new Date();
        startOfMonth.setDate(1);
        startOfMonth.setHours(0, 0, 0, 0);
        const monthlyCommits = await Commits.count({
            where: {
                wallet: addr,
                date: { [Op.gte]: startOfMonth }
            }
        });

        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        const newCommit = await Commits.create({
            wallet: addr,
            link: link,
            ip_address: ip,
            category: category
        });

        console.log('New commit added:', { wallet: addr, link: link });

        if (monthlyCommits >= 6) {
            return res.status(200).json({
                message: 'Thank you for your submission! Please note that you have exceeded 6 submissions this month. Only your 6 highest-quality submissions will be considered in the same category.'
            });
        }

        res.status(200).json({ message: 'Thank you for your submission!' });

    } catch (error) {
        console.error('Error submitting link:', error);
        res.status(500).json({ error: 'Server error. Please try again later.' });
    }
});



app.get('/jsonmodo', authorizationmodo, async (req, res) => {
    try {
        const moderatorWallet = req.modo.username;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 14;
        const offset = (page - 1) * limit;

        const queryCondition = {
            include: [{
                model: Vote,
                required: false,
                where: { wallet_id: moderatorWallet },
                attributes: ['vote_value', 'vote_date']
            }],
            distinct: true,
            order: [['id', 'DESC']],
            limit: limit,
            offset: offset
        };

        const totalResults = await Commits.count({ distinct: true });
        const totalPages = Math.ceil(totalResults / limit);

        if (page > totalPages && totalPages > 0) {
            return res.status(404).json({
                error: `Page ${page} does not exist. The last page is ${totalPages}.`
            });
        }

        const commits = await Commits.findAll(queryCondition);

        const result = commits.map(commit => ({
            id: commit.id,
            link: commit.link,
            wallet: commit.wallet,
            date: commit.date,
            category: commit.category,
            views: commit.views,
            vote: commit.Votes.length > 0 ? {
                value: commit.Votes[0].vote_value,
                date: commit.Votes[0].vote_date
            } : null
        }));

        res.json({
            total: totalPages,
            currentPage: page,
            limit,
            totalResults,
            hasNextPage: page < totalPages,
            hasPreviousPage: page > 1,
            commits: result
        });
    } catch (error) {
        console.error('Error fetching moderation data:', error);
        res.status(500).json({ 
            error: 'An error occurred while fetching moderation data.',
            details: error.message 
        });
    }
});



app.get('/json', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const wallet = req.query.wallet;
        const offset = (page - 1) * limit;

        const baseCondition = {
            include: [{
                model: Vote,
                ...(wallet ? {} : {
                    where: {
                        vote_value: {
                            [Op.gt]: 0
                        }
                    },
                    required: true
                }),
                required: wallet ? false : true
            }],
            distinct: true,
            logging: false
        };

        if (wallet) {
            baseCondition.where = {
                wallet: wallet
            };
        }

        const totalResults = await Commits.count(baseCondition);
        const totalPages = Math.ceil(totalResults / limit);

        if (page > totalPages) {
            return res.status(404).json({
                error: `Page ${page} does not exist. The last page is ${totalPages}.`
            });
        }

        const queryCondition = {
            ...baseCondition,
            order: [['id', 'DESC']],
            limit: limit,
            offset: offset
        };

        const commits = await Commits.findAll(queryCondition);

        const result = commits.map(commit => ({
            link: commit.link,
            wallet: commit.wallet,
            date: commit.date,
            category: commit.category,
            views: commit.views
        }));

        res.json({
            total: totalPages,
            currentPage: page,
            limit,
            totalResults,
            hasNextPage: page < totalPages,
            hasPreviousPage: page > 1,
            wallet: wallet || 'all',
            commits: result
        });

    } catch (error) {
        console.error('Error fetching commits:', error);
        res.status(500).json({ 
            error: 'An error occurred while fetching commits.',
            details: error.message 
        });
    }
});


app.get('/stats', async (req, res) => {
    try {
        const { wallet } = req.query;
        const whereClause = wallet ? { wallet } : {};

        const stats = await Commits.findAll({
            where: whereClause,
            attributes: [
                [Sequelize.fn('DATE', Sequelize.col('date')), 'date'],
                [Sequelize.fn('SUM', Sequelize.col('views')), 'total_views']
            ],
            group: ['date'],
            order: [['date', 'ASC']],
            raw: true
        });

        const dataset = stats.map(stat => ({
            date: stat.date,
            views: parseInt(stat.total_views)
        }));

        res.json(dataset);
    } catch (error) {
        console.error('Erreur lors de la récupération des stats:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});




async function authenticate(req, res, next) {
    const { stakeAddress, signature, message, publicKey } = req.body;
    console.log(stakeAddress);
    if (!stakeAddress || !signature || !message || !publicKey) {
        return res.status(400).json({ success: false, message: 'Données manquantes' });
    }

    try { 
        const sigBuffer = Buffer.from(signature, "hex");
        const decodedSig = cbor.decodeFirstSync(sigBuffer);
        const protectedHeader = decodedSig[0];
        const payload = decodedSig[2];
        const signatureBytes = decodedSig[3];

        if (signatureBytes.length !== 64) {
            throw new Error(`Invalid signature length: ${signatureBytes.length} bytes (expected 64)`);
        }

        const keyBuffer = Buffer.from(publicKey, "hex");
        const decodedKey = cbor.decodeFirstSync(keyBuffer);

        const publicKeyBytes = decodedKey.get(-2);
        if (!publicKeyBytes || publicKeyBytes.length !== 32) {
            throw new Error(`Invalid public key length: ${publicKeyBytes?.length || 0} bytes (expected 32)`);
        }
        const { verify, etc } = await import('@noble/ed25519');
        etc.sha512Sync = (...msgs) => {
            const hash = crypto.createHash('sha512');
            for (const msg of msgs) hash.update(msg);
            return hash.digest();
        };

        // build Sig_structure (CIP-8)
        const sigStructure = cbor.encode([
            "Signature1",
            protectedHeader,
            Buffer.from(""), // external_aad (empty)
            payload
        ]);
        const isVerified = await verify(signatureBytes, sigStructure, publicKeyBytes);
        if (!isVerified) {
            return res.status(401).json({
                success: false,
                message: "Fail during signature verification...",
                debug: {
                    payloadHex: payload.toString('hex'),
                    messageHex: Buffer.from(message).toString('hex')
                }
            });
        }

        console.log("Signature verification successful!");

               let signerStakeAddrBech32 = stakeAddress;
        if (!stakeAddress.startsWith('stake1')) {
            const rewardAddress = RewardAddress.from_address(Address.from_bytes(Buffer.from(stakeAddress, 'hex')));
            if (!rewardAddress) {
                throw new Error('Invalid stake address hex format');
            }
            signerStakeAddrBech32 = rewardAddress.to_address().to_bech32();
        }
        const rewardAddress = RewardAddress.from_address(Address.from_bech32(signerStakeAddrBech32));
        const signerIsRegistered = registeredUsers.includes(signerStakeAddrBech32);

        const token = signerIsRegistered
            ? await generateJWTmodo(rewardAddress, signerStakeAddrBech32)
            : await generateJWT(rewardAddress, signerStakeAddrBech32);

        res.cookie('token', token, { httpOnly: true });
        return res.json({ success: true, token });
    } catch (error) {
        console.error("Authentication error:", error);
        return res.status(500).json({
            success: false,
            message: `Error: ${error.message}`
        });
    }
}
async function generateJWT(address, signerStakeAddrBech32) {
    const payload = {
        username: address,
        stakeKey: signerStakeAddrBech32
    };
    const token = jwt.sign(payload, secret, { expiresIn: '1h' });
    return token;
}

async function generateJWTmodo(address, signerStakeAddrBech32) {
    const payload = {
        username: address,
        stakeKey: signerStakeAddrBech32
    };
    const token = jwt.sign(payload, secret2, { expiresIn: '1h' });
    return token;
}
