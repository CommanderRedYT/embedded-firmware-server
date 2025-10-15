import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import Database from 'better-sqlite3';
import commander from 'commander';
import crypto from 'crypto';
import morgan from 'morgan';
import packageJson from '../package.json';

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

app.use(morgan('combined'));

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
    /*db.exec(`
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
        ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS force_upgrade_on_unknown INTEGER DEFAULT 0;
    `);*/
    const migrations = [
        `CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT OR IGNORE INTO meta (key, value) VALUES ('db_version', '0');`,
        `CREATE TABLE IF NOT EXISTS firmware (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            device_type TEXT NOT NULL,
            version TEXT NOT NULL,
            file_path TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );`,
        `CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL UNIQUE,
            api_key TEXT NOT NULL UNIQUE
        );`,
        `CREATE INDEX IF NOT EXISTS idx_firmware_project_device ON firmware (project_id, device_type);`,
        `ALTER TABLE api_keys ADD COLUMN force_upgrade_on_unknown INTEGER DEFAULT 0;`
    ];

    let currentVersion = 0;

    try {
        const getVersionStmt = db.prepare('SELECT value FROM meta WHERE key = ?');
        const row = getVersionStmt.get('db_version') as { value: string } | undefined;
        if (row) {
            currentVersion = parseInt(row.value, 10);
        }
    } catch {
        console.log('Meta table does not exist, looks like a fresh database.');
    }

    let didSomething = false;

    for (let i = currentVersion; i < migrations.length; i++) {
        const migration = migrations[i];

        if (!migration) continue;

        console.log(`Applying migration version ${i + 1}`);

        db.exec(migration);
        currentVersion++;
        const setVersionStmt = db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)');
        setVersionStmt.run('db_version', currentVersion.toString());
        console.log(`Applied migration version ${currentVersion}`);
        didSomething = true;
    }

    if (didSomething) {
        console.log('Database setup complete. Current version:', currentVersion);
    }
};

setupDatabase();

const hasNewerFirmware = (currentHash: string, project_id: string, force_upgrade_on_unknown: boolean): boolean => {
    if (!currentHash) return true;

    // if currentHash is not in our database, return false
    const stmt = db.prepare('SELECT COUNT(*) as count FROM firmware WHERE version = ? AND project_id = ?');
    const row = stmt.get(currentHash, project_id) as { count: number };

    if (row.count === 0) {
        console.warn('Current firmware hash not found in database for project:', project_id);
        return false;
    }

    // Get the hash of the latest firmware
    const latestStmt = db.prepare('SELECT version FROM firmware WHERE project_id = ? ORDER BY upload_date DESC LIMIT 1');
    const latestRow = latestStmt.get(project_id) as { version: string } | undefined;

    if (!latestRow) {
        console.warn('No firmware found in database for project:', project_id);
        return force_upgrade_on_unknown;
    }

    const isSame = latestRow.version === currentHash;

    console.log(`Comparing firmware hashes: current=${currentHash}, latest=${latestRow.version}, isSame=${isSame}`);

    return !isSame;
}

// Add command-line option for database reset and creating a new API key
const command = new commander.Command();

command.name('firmware-server')
    .description('Firmware Management Server')
    .version(packageJson.version);

// split flags into commands
command
    .command('reset-db')
    .description('Reset the database (deletes all data)')
    .action(() => {
        db.exec('DROP TABLE IF EXISTS firmware;');
        setupDatabase();
        console.log('Database has been reset.');
        process.exit(0);
    });

command
    .command('create-api-key <project_id>')
    .option('--force-upgrade-on-unknown', 'Force upgrade on unknown firmware versions', false)
    .description('Create a new API key for the specified project ID')
    .action((projectId: string, options: { forceUpgradeOnUnknown: boolean }) => {
        const apiKey = crypto.randomBytes(16).toString('hex');

        const insert = db.prepare('INSERT INTO api_keys (project_id, api_key, force_upgrade_on_unknown) VALUES (?, ?, ?)');
        try {
            insert.run(projectId, apiKey, options.forceUpgradeOnUnknown ? 1 : 0);
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
    });

command
    .command('get-api-keys')
    .description('List all API keys')
    .action(() => {
        const stmt = db.prepare('SELECT project_id, api_key FROM api_keys');
        const rows = stmt.all() as { project_id: string; api_key: string }[];
        if (rows.length === 0) {
            console.log('No API keys found.');
        } else {
            rows.forEach(row => {
                console.log(`Project ID: ${row.project_id}, API Key: ${row.api_key}`);
            });
        }
        process.exit(0);
    });

command
    .command('get-firmware <project_id> <device_type>')
    .description('Get latest firmware for a specific project and device type')
    .action((projectId: string, deviceType: string) => {
        const stmt = db.prepare(`
        SELECT * FROM firmware 
        WHERE project_id = ? AND device_type = ? 
        ORDER BY upload_date DESC 
        LIMIT 1
    `);
        const firmware = stmt.get(projectId, deviceType) as {
            id: number;
            project_id: string;
            device_type: string;
            version: string;
            upload_date: string;
        } | undefined;

        if (!firmware) {
            console.log('No firmware found for the specified project and device type.');
        } else {
            console.log(`ID: ${firmware.id}`);
            console.log(`Project ID: ${firmware.project_id}`);
            console.log(`Device Type: ${firmware.device_type}`);
            console.log(`Version: ${firmware.version}`);
            console.log(`Upload Date: ${firmware.upload_date}`);
        }
        process.exit(0);
    });

command
    .command('list-firmwares <project_id>')
    .description('List all firmware entries for a specific project')
    .action((projectId: string) => {
        const stmt = db.prepare('SELECT * FROM firmware WHERE project_id = ? ORDER BY upload_date DESC');
        const firmwares = stmt.all(projectId) as {
            id: number;
            project_id: string;
            device_type: string;
            version: string;
            upload_date: string;
        }[];

        if (firmwares.length === 0) {
            console.log('No firmware entries found for the specified project.');
        } else {
            firmwares.forEach(firmware => {
                console.log(`ID: ${firmware.id}, Device Type: ${firmware.device_type}, Version: ${firmware.version}, Upload Date: ${firmware.upload_date}`);
            });
        }
        process.exit(0);
    });

command
    .command('delete-api-key <project_id>')
    .description('Delete the API key for the specified project ID')
    .action((projectId: string) => {
        const del = db.prepare('DELETE FROM api_keys WHERE project_id = ?');
        const result = del.run(projectId);
        if (result.changes === 0) {
            console.log(`No API key found for project ID "${projectId}".`);
        } else {
            console.log(`API key for project ID "${projectId}" has been deleted.`);
        }
        process.exit(0);
    });

command
    .command('delete-firmware <firmware_id>')
    .description('Delete the firmware entry with the specified ID')
    .action((firmwareId: string) => {
        const getStmt = db.prepare('SELECT file_path FROM firmware WHERE id = ?');
        const firmware = getStmt.get(firmwareId) as { file_path: string } | undefined;

        if (!firmware) {
            console.log(`No firmware entry found with ID "${firmwareId}".`);
            process.exit(0);
        }

        const del = db.prepare('DELETE FROM firmware WHERE id = ?');
        const result = del.run(firmwareId);
        if (result.changes > 0) {
            // Delete the associated file
            fs.unlink(firmware.file_path, err => {
                if (err) {
                    console.error('Error deleting firmware file:', err.message);
                } else {
                    console.log('Associated firmware file deleted.');
                }
            });
            console.log(`Firmware entry with ID "${firmwareId}" has been deleted.`);
        } else {
            console.log(`No firmware entry found with ID "${firmwareId}".`);
        }
        process.exit(0);
    });

command
    .command('cleanup-upload-dir')
    .description('Delete all files in the uploads directory that are not referenced in the database')
    .action(() => {
        const stmt = db.prepare('SELECT file_path FROM firmware');
        const rows = stmt.all() as { file_path: string }[];
        const validFiles = new Set(rows.map(row => path.resolve(row.file_path)));

        const files = fs.readdirSync(uploadDir);
        let deletedCount = 0;

        for (const file of files) {
            const filePath = path.resolve(path.join(uploadDir, file));
            if (!validFiles.has(filePath)) {
                fs.unlinkSync(filePath);
                console.log(`Deleted unreferenced file: ${filePath}`);
                deletedCount++;
            }
        }

        console.log(`Cleanup complete. Deleted ${deletedCount} unreferenced files.`);
        process.exit(0);
    });

command
    .command('prune-old-firmwares <days>')
    .description('Delete firmware entries older than the specified number of days')
    .action((daysString: string) => {
        const days = parseInt(daysString, 10);
        if (isNaN(days) || days <= 0) {
            console.error('Please provide a valid number of days.');
            process.exit(1);
        }

        const cutoffDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

        const getStmt = db.prepare('SELECT id, file_path FROM firmware WHERE upload_date < ?');
        const oldFirmwares = getStmt.all(cutoffDate) as { id: number; file_path: string }[];

        const delStmt = db.prepare('DELETE FROM firmware WHERE id = ?');
        let deletedCount = 0;

        for (const firmware of oldFirmwares) {
            const result = delStmt.run(firmware.id);
            if (result.changes > 0) {
                // Delete the associated file
                fs.unlink(firmware.file_path, err => {
                    if (err) {
                        console.error('Error deleting firmware file:', err.message);
                    } else {
                        console.log(`Deleted firmware file: ${firmware.file_path}`);
                    }
                });
                deletedCount++;
            }
        }

        console.log(`Pruned ${deletedCount} firmware entries older than ${days} days.`);
        process.exit(0);
    });

command
    .command('prune-except-latest')
    .description('Keep only the latest firmware entry for each project and device type, delete the rest')
    .action(() => {
        const getProjectsStmt = db.prepare('SELECT DISTINCT project_id, device_type FROM firmware');
        const projects = getProjectsStmt.all() as { project_id: string; device_type: string }[];

        const delStmt = db.prepare('DELETE FROM firmware WHERE id = ?');
        let deletedCount = 0;

        for (const { project_id, device_type } of projects) {
            const getFirmwaresStmt = db.prepare(`
            SELECT id, file_path FROM firmware 
            WHERE project_id = ? AND device_type = ? 
            ORDER BY upload_date DESC
        `);
            const firmwares = getFirmwaresStmt.all(project_id, device_type) as { id: number; file_path: string }[];

            // Keep the latest one, delete the rest
            for (let i = 1; i < firmwares.length; i++) {
                const firmware = firmwares[i];

                if (!firmware) continue;

                const result = delStmt.run(firmware.id);
                if (result.changes > 0) {
                    // Delete the associated file
                    fs.unlink(firmware.file_path, err => {
                        if (err) {
                            console.error('Error deleting firmware file:', err.message);
                        } else {
                            console.log(`Deleted firmware file: ${firmware.file_path}`);
                        }
                    });
                    deletedCount++;
                }
            }
        }

        console.log(`Pruned ${deletedCount} old firmware entries, keeping only the latest for each project and device type.`);
        process.exit(0);
    });

// command to edit projects options like force_upgrade_on_unknown
command
    .command('set-force-upgrade <project_id> <value>')
    .description('Set force_upgrade_on_unknown option for a specific project (true/false)')
    .action((projectId: string, value: string) => {
        const boolValue = value.toLowerCase() === 'true' ? 1 : 0;

        const updateStmt = db.prepare('UPDATE api_keys SET force_upgrade_on_unknown = ? WHERE project_id = ?');
        const result = updateStmt.run(boolValue, projectId);

        if (result.changes === 0) {
            console.log(`No project found with ID "${projectId}".`);
        } else {
            console.log(`Set force_upgrade_on_unknown to ${boolValue} for project ID "${projectId}".`);
        }
        process.exit(0);
    });

if (process.argv.length > 2) {
    command.parse(process.argv);
} else {
    console.log('No command specified, starting server...');
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

    console.log(`Firmware uploaded: Project ID=${projectId}, Device Type=${device_type}, Version=${version}, File Path=${filePath}`);

    res.status(201).json({message: 'Firmware uploaded successfully'});
});

const doFileDownload = (id: string, projectId: string, res: express.Response) => {
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
}

// Route to get latest firmware
app.get('/api/v1/firmware/latest', authenticate, (req: ExpressRequestWithProjectId, res) => {
    const {device_type} = req.query;
    const projectId = req.projectId;

    if (!device_type) {
        return res.status(400).json({error: 'device_type is required'});
    }

    if (!projectId) {
        return res.status(500).json({error: 'Project ID not found in request'});
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

    const projectStmt = db.prepare('SELECT force_upgrade_on_unknown FROM api_keys WHERE project_id = ?');
    const projectRow = projectStmt.get(projectId) as { force_upgrade_on_unknown: number } | undefined;
    const force_upgrade_on_unknown = projectRow ? projectRow.force_upgrade_on_unknown === 1 : false;

    // This header can be used to check if we need to update. If the version matches, we can send a not-modified response.
    const xEsp32Version = req.header('X-ESP32-Version');

    // if it exists, directly download the file
    if (xEsp32Version) {
        console.log(`Device with version ${xEsp32Version} is downloading firmware ID ${firmware.id}`);
        const isNewer = hasNewerFirmware(xEsp32Version, projectId, force_upgrade_on_unknown);
        if (!isNewer) {
            console.log(`Device firmware is up to date (version: ${xEsp32Version}). Sending 304 Not Modified.`);
            return res.status(304).end();
        }

        console.log(`Device firmware is outdated (current: ${xEsp32Version}, latest: ${firmware.version}). Sending firmware file.`);

        return doFileDownload(firmware.id.toString(), projectId, res);
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

    if (!projectId) {
        return res.status(500).json({error: 'Project ID not found in request'});
    }

    if (!id) {
        return res.status(400).json({error: 'Firmware ID is required'});
    }

    doFileDownload(id, projectId, res);
});

// fallback to no content
app.use((_, res) => {
    res.status(204).end();
});

// Start the server
app.listen(PORT, HOST, () => {
    console.log(`Server is running on http://${HOST}:${PORT}`);
});
