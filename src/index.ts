import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import Database from 'better-sqlite3';
import commander from 'commander';
import crypto from 'crypto';

/*
 * ==== API Routes ====
 * X-API-Key: A api key that maps to a specific project
 * ====================
 * POST /api/v1/firmware - Upload firmware file. Requires X-API-Key header. Also contains version and device_type fields
 * GET /api/v1/firmware/latest?project_id=PROJECT_ID&device_type=DEVICE_TYPE - Get latest firmware for a specific project and device type. Requires X-API-Key header.
 * ===================
 * All files are stored in ./data/uploads directory. The ./data directory also contains a SQLite database file (data.db) that stores metadata about the uploaded firmware files.
 * ===================
*/

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');

const HOST = process.env.HOST || 'localhost';
const PORT = parseInt(process.env.PORT || '3000');

const dataDir = path.resolve('data');
const uploadDir = path.join(dataDir, 'uploads');
const dbPath = path.join(dataDir, 'data.db');

// Ensure data and upload directories exist
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
}
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Initialize SQLite database
const db = new Database(dbPath);

const setupDatabase = () => {
    db.exec(`
        CREATE TABLE IF NOT EXISTS firmware (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            device_type TEXT NOT NULL,
            version TEXT NOT NULL,
            file_path TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL UNIQUE,
            api_key TEXT NOT NULL UNIQUE
        );
        CREATE INDEX IF NOT EXISTS idx_firmware_project_device ON firmware (project_id, device_type);
    `);
};

setupDatabase();


// Add command-line option for database reset and creating a new API key
const command = new commander.Command();

command
    .option('--reset-db', 'Reset the database (deletes all data)')
    .option('--create-api-key <project_id>', 'Create a new API key for the specified project ID')
    .parse(process.argv);

const options = command.opts();

if (options.resetDb) {
    db.exec('DROP TABLE IF EXISTS firmware;');
    setupDatabase();
    console.log('Database has been reset.');
    process.exit(0);
}

if (options.createApiKey) {
    const projectId = options.createApiKey;
    const apiKey = crypto.randomBytes(16).toString('hex');

    const insert = db.prepare('INSERT INTO api_keys (project_id, api_key) VALUES (?, ?)');
    try {
        insert.run(projectId, apiKey);
        console.log(`API key for project "${projectId}": ${apiKey}`);
    } catch (err) {
        if (err instanceof Error) {
            if (err.message.includes('UNIQUE constraint failed: api_keys.project_id')) {
                console.error(`Project ID "${projectId}" already has an API key.`);
            } else {
                console.error('Error creating API key:', err.message);
            }
        }
    }
    process.exit(0);
}

// Middleware to parse JSON bodies
app.use(express.json());

// Middleware for handling file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({storage: storage});

type ExpressRequestWithProjectId = express.Request & { projectId?: string };

// Middleware to check API key
const authenticate: express.Handler = (req: ExpressRequestWithProjectId, res, next) => {
    const apiKey = req.header('X-API-Key');
    if (!apiKey) {
        return res.status(401).json({error: 'API key is required'});
    }

    const stmt = db.prepare('SELECT project_id FROM api_keys WHERE api_key = ?');
    const row = stmt.get(apiKey) as { project_id: string } | undefined;
    if (!row) {
        return res.status(403).json({error: 'Invalid API key'});
    }

    req.projectId = row.project_id;
    next();
};

// Route to upload firmware
app.post('/api/v1/firmware', authenticate, upload.single('firmware'), (req: ExpressRequestWithProjectId, res) => {
    const {version, device_type} = req.body;
    const projectId = req.projectId;

    if (!version || !device_type) {
        return res.status(400).json({error: 'Version and device_type are required'});
    }
    if (!req.file) {
        return res.status(400).json({error: 'Firmware file is required'});
    }

    const filePath = req.file.path;

    const insert = db.prepare('INSERT INTO firmware (project_id, device_type, version, file_path) VALUES (?, ?, ?, ?)');
    insert.run(projectId, device_type, version, filePath);

    res.status(201).json({message: 'Firmware uploaded successfully'});
});

// Route to get latest firmware
app.get('/api/v1/firmware/latest', authenticate, (req: ExpressRequestWithProjectId, res) => {
    const {device_type} = req.query;
    const projectId = req.projectId;

    if (!device_type) {
        return res.status(400).json({error: 'device_type is required'});
    }

    const stmt = db.prepare(`
        SELECT * FROM firmware 
        WHERE project_id = ? AND device_type = ? 
        ORDER BY upload_date DESC 
        LIMIT 1
    `);
    const firmware = stmt.get(projectId, device_type) as {
        id: number;
        project_id: string;
        device_type: string;
        version: string;
        upload_date: string;
    } | undefined;

    if (!firmware) {
        return res.status(404).json({error: 'No firmware found for the specified project and device type'});
    }

    res.json({
        id: firmware.id,
        project_id: firmware.project_id,
        device_type: firmware.device_type,
        version: firmware.version,
        upload_date: firmware.upload_date,
        download_url: `/api/v1/firmware/download/${firmware.id}`
    });
});

// Route to download firmware file
app.get('/api/v1/firmware/download/:id', authenticate, (req: ExpressRequestWithProjectId, res) => {
    const {id} = req.params;
    const projectId = req.projectId;

    const stmt = db.prepare('SELECT * FROM firmware WHERE id = ? AND project_id = ?');
    const firmware = stmt.get(id, projectId) as { file_path: string } | undefined;

    if (!firmware) {
        return res.status(404).json({error: 'Firmware not found'});
    }

    res.download(firmware.file_path, err => {
        if (err) {
            res.status(500).json({error: 'Error downloading file'});
        }
    });
});

// fallback to no content
app.use((_, res) => {
    res.status(204).end();
});

// Start the server
app.listen(PORT, HOST, () => {
    console.log(`Server is running on http://${HOST}:${PORT}`);
});
