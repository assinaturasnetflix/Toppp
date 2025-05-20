// ==========================================================================
// PARTE 1: IMPORTS, CONFIGURAÇÃO INICIAL, CONEXÃO DB, MODELOS MONGOOSE
// ==========================================================================

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto'); // Para gerar códigos de referência mais robustos

// Carregar variáveis de ambiente do arquivo .env
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;

// --- Conexão com o Banco de Dados MongoDB ---
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB Conectado com Sucesso!'))
.catch(err => {
    console.error('Erro ao conectar com MongoDB:', err.message);
    process.exit(1); // Sair do processo com falha se não conseguir conectar ao DB
});

// --- Middlewares Globais ---
app.use(cors({ // Permite requisições de qualquer origem
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json()); // Para parsear o corpo das requisições JSON

// Servir arquivos estáticos do front-end da pasta 'public'
app.use(express.static(__dirname));


// --- Definição dos Esquemas e Modelos Mongoose ---

// Esquema do Usuário (User)
const UserSchema = new mongoose.Schema({
    name: { type: String, required: [true, "Nome é obrigatório"], trim: true },
    email: { type: String, required: [true, "Email é obrigatório"], unique: true, trim: true, lowercase: true, match: [/\S+@\S+\.\S+/, 'Email inválido'] },
    password: { type: String, required: [true, "Senha é obrigatória"], minlength: [6, "Senha deve ter no mínimo 6 caracteres"] },
    securityQuestion: { type: String, required: [true, "Pergunta de segurança é obrigatória"] },
    securityAnswer: { type: String, required: [true, "Resposta de segurança é obrigatória"] },
    referralCode: { type: String, unique: true, sparse: true },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    balance: { type: Number, default: 200.00, min: 0 },
    bonusBalance: { type: Number, default: 0.00, min: 0 },
    totalInvested: { type: Number, default: 0.00, min: 0 },
    activePlanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', default: null },
    activePlanActivationDate: { type: Date },
    dailyClaims: [{ // Claims feitos para o plano ativo ATUAL
        claimIndex: { type: Number }, // 0 a 4
        currency: { type: String },
        amount: { type: Number },
        claimedAt: { type: Date }
    }],
    lastClaimResetDate: { type: String }, // Formato YYYY-MM-DD
    isBlocked: { type: Boolean, default: false },
    firstDepositMade: { type: Boolean, default: false },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', async function (next) {
    if (this.isModified('updatedAt') && !this.isNew) { // Atualiza updatedAt apenas se não for um novo doc e algo mudou
        this.updatedAt = Date.now();
    }
    if (!this.isModified('password') && !this.isModified('securityAnswer')) return next();

    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    if (this.isModified('securityAnswer')) {
        const salt = await bcrypt.genSalt(10);
        this.securityAnswer = await bcrypt.hash(this.securityAnswer, salt);
    }
    next();
});
UserSchema.methods.matchPassword = async function (enteredPassword) { return await bcrypt.compare(enteredPassword, this.password); };
UserSchema.methods.matchSecurityAnswer = async function (enteredAnswer) { return await bcrypt.compare(enteredAnswer, this.securityAnswer); };
const User = mongoose.model('User', UserSchema);


// Esquema dos Planos de Investimento (Plan)
const PlanSchema = new mongoose.Schema({
    planIdentifier: { type: String, required: true, unique: true }, // Ex: "plan_500", "plan_1000"
    name: { type: String, required: true },
    value: { type: Number, required: true },
    dailyPercentage: { type: Number, required: true },
    dailyProfitMT: { type: Number, required: true },
    totalClaimsPerDay: { type: Number, default: 5 },
    claimsSplit: [{ currency: { type: String, required: true }, amount: { type: Number, required: true } }],
    lifetime: { type: Boolean, default: true },
    isActive: { type: Boolean, default: true }, // Para admin (des)ativar
    order: { type: Number, default: 0 } // Para ordenar na exibição
});
const Plan = mongoose.model('Plan', PlanSchema);


// Esquema dos Depósitos (Deposit)
const DepositSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: [50, "Depósito mínimo de 50 MT"] },
    currency: { type: String, default: 'MT' }, // Futuramente, pode ser BTC, ETH...
    methodId: { type: String, required: true }, // ID do AdminPaymentMethod (ex: 'mpesa_main', 'btc_wallet1')
    methodName: { type: String, required: true }, // Nome do método para exibição
    transactionIdUser: { type: String, required: true, trim: true }, // ID/comprovante do usuário
    status: { type: String, enum: ['Pending', 'Confirmed', 'Rejected'], default: 'Pending' },
    adminNotes: { type: String },
    planToActivate: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', default: null },
    createdAt: { type: Date, default: Date.now },
    confirmedAt: { type: Date },
    updatedAt: { type: Date, default: Date.now }
});
DepositSchema.pre('save', function(next){ this.updatedAt = Date.now(); next(); });
const Deposit = mongoose.model('Deposit', DepositSchema);


// Esquema dos Saques (Withdrawal)
const WithdrawalSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amountRequested: { type: Number, required: true, min: [50, "Saque mínimo de 50 MT"], max: [50000, "Saque máximo de 50.000 MT"] },
    feePercentage: { type: Number, required: true }, // Taxa % aplicada
    feeAmount: { type: Number, required: true },     // Valor da taxa em MT
    amountToReceive: { type: Number, required: true }, // amountRequested - feeAmount
    methodId: { type: String, required: true },      // ID do AdminPaymentMethod
    methodName: { type: String, required: true },
    recipientAddress: { type: String, required: true, trim: true }, // Número ou carteira do usuário
    status: { type: String, enum: ['Pending', 'Processing', 'Completed', 'Rejected', 'Cancelled'], default: 'Pending' },
    adminNotes: { type: String },
    transactionHashAdmin: { type: String }, // Hash da transação de envio pelo admin
    createdAt: { type: Date, default: Date.now },
    processedAt: { type: Date },
    updatedAt: { type: Date, default: Date.now }
});
WithdrawalSchema.pre('save', function(next){ this.updatedAt = Date.now(); next(); });
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);


// Esquema de Transações Gerais (Transaction) - para histórico unificado
const TransactionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: {
        type: String,
        enum: ['deposit', 'withdrawal', 'claim_income', 'bonus_signup', 'bonus_referral', 'plan_activation', 'withdrawal_fee', 'admin_credit', 'admin_debit'],
        required: true
    },
    amount: { type: Number, required: true }, // Positivo para créditos, negativo para débitos no saldo principal
    currency: { type: String, required: true, default: 'MT' },
    description: { type: String, required: true },
    status: { type: String }, // Ex: 'Pending', 'Completed', 'Failed' (relevante p/ depósitos/saques)
    relatedRecord: { // ID do registro original (Deposit, Withdrawal, User para bônus, etc.)
        recordId: { type: mongoose.Schema.Types.ObjectId },
        recordModel: { type: String } // 'Deposit', 'Withdrawal', etc.
    },
    balanceBefore: { type: Number }, // Saldo principal antes da transação
    balanceAfter: { type: Number },  // Saldo principal após a transação
    bonusBalanceBefore: { type: Number },
    bonusBalanceAfter: { type: Number },
    createdAt: { type: Date, default: Date.now, index: true }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);


// Esquema de Notificações (Notification)
const NotificationSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true, default: null }, // null para global
    title: { type: String, required: true },
    message: { type: String, required: true },
    fullMessage: { type: String },
    type: { type: String, enum: ['info', 'success', 'warning', 'error', 'promo', 'system'], default: 'info' },
    displayType: { type: String, enum: ['modal', 'banner', 'alert'], default: 'alert' }, // Como admin quer que apareça
    read: { type: Boolean, default: false },
    actionUrl: { type: String },
    actionText: { type: String },
    isGlobal: { type: Boolean, default: false }, // Se true e user for null, é para todos os usuários logados
    expiresAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', NotificationSchema);


// Esquema do Histórico de Referências (ReferralHistory)
const ReferralHistorySchema = new mongoose.Schema({
    referrer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    referredUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    bonusAmount: { type: Number, default: 65 },
    status: { type: String, enum: ['PendingValidation', 'BonusAwardedToBonusBalance', 'BonusReleasedToMainBalance', 'Invalidated'], default: 'PendingValidation' },
    awardedAt: { type: Date },   // Quando o bônus foi para o bonusBalance do referrer
    releasedAt: { type: Date },  // Quando o bônus foi para o mainBalance do referrer
    createdAt: { type: Date, default: Date.now }
});
const ReferralHistory = mongoose.model('ReferralHistory', ReferralHistorySchema);


// Esquema de Configurações do Admin (AdminConfig) e Métodos de Pagamento
const AdminPaymentMethodSchema = new mongoose.Schema({
    _id: { type: mongoose.Schema.Types.ObjectId, auto: true }, // Garante um _id
    methodIdentifier: { type: String, required: true, unique: true }, // Ex: "mpesa_1", "btc_cold", "usdt_trc20_main"
    name: { type: String, required: true }, // Ex: "Mpesa Principal", "Carteira BTC Investimentos"
    type: { type: String, enum: ['mobile_money', 'crypto', 'bank'], required: true },
    currencyForCrypto: { type: String }, // Ex: BTC, ETH, USDT (só para type='crypto')
    network: { type: String }, // Ex: Bitcoin, ERC20, TRC20, BEP20 (só para type='crypto')
    address: { type: String, required: true }, // Número do Mpesa/Emola ou endereço da carteira
    instructionsForUser: { type: String },
    isActiveForDeposit: { type: Boolean, default: true },
    isActiveForWithdrawal: { type: Boolean, default: true },
    minDeposit: { type: Number, default: 50 },
    maxDeposit: { type: Number, default: 1000000 },
    minWithdrawal: { type: Number, default: 50 },
    maxWithdrawal: { type: Number, default: 50000 },
    withdrawalFeePercentage: { type: Number, default: 2, min:0, max:100 } // Taxa percentual (2 para 2%)
});

const SiteTextSchema = new mongoose.Schema({ // Subdocumento para textos
    _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
    key: { type: String, unique: true, required: true }, // Ex: 'login_contact_info', 'register_security_note'
    value: { type: String, required: true },
    locationHint: { type: String } // Ex: "Login Page", "User Dashboard"
});

const AdminConfigSchema = new mongoose.Schema({
    // Usaremos um único documento para AdminConfig, identificado por um campo fixo.
    configName: { type: String, default: "mainConfig", unique: true },
    paymentMethods: [AdminPaymentMethodSchema],
    siteTexts: [SiteTextSchema],
    nextReferralSuffix: { type: Number, default: 1001 }, // Para gerar códigos de referência
    // Outras configurações globais podem ir aqui
});
const AdminConfig = mongoose.model('AdminConfig', AdminConfigSchema);


// --- Middleware de Autenticação JWT (Protect Routes) ---
const protect = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = await User.findById(decoded.id).select('-password -securityAnswer');

            if (!req.user) {
                return res.status(401).json({ success: false, message: 'Não autorizado, usuário não encontrado.' });
            }
            if (req.user.isBlocked) {
                 return res.status(403).json({ success: false, message: 'Sua conta está bloqueada.' });
            }
            next();
        } catch (error) {
            console.error('Erro na autenticação do token:', error.message);
            const message = error.name === 'JsonWebTokenError' ? 'Token inválido.' :
                            error.name === 'TokenExpiredError' ? 'Token expirado.' :
                            'Não autorizado, token falhou.';
            return res.status(401).json({ success: false, message });
        }
    }
    if (!token) {
        return res.status(401).json({ success: false, message: 'Não autorizado, sem token.' });
    }
};

// Middleware para rotas de Admin
const adminProtect = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ success: false, message: 'Acesso negado. Rota de administrador.' });
    }
};

// --- Funções Utilitárias ---
function generateUserReferralCode(name, suffix) {
    const namePart = name.substring(0, Math.min(name.length, 4)).toUpperCase().replace(/\s+/g, '');
    return `${namePart}${suffix}`;
}

// Função para registrar transação
async function recordTransaction(userId, type, amount, currency, description, status, relatedRecord = {}, balanceBefore = null, balanceAfter = null, bonusBalanceBefore = null, bonusBalanceAfter = null) {
    try {
        const transactionData = {
            user: userId, type, amount, currency, description, status,
            relatedRecord: {
                recordId: relatedRecord.id || null,
                recordModel: relatedRecord.model || null
            },
            // Os saldos podem ser buscados ou passados se já conhecidos e consistentes
            // Para simplificar, não vamos adicionar balanceBefore/After por enquanto, mas é uma boa prática
        };
        if (balanceBefore !== null) transactionData.balanceBefore = balanceBefore;
        if (balanceAfter !== null) transactionData.balanceAfter = balanceAfter;
        if (bonusBalanceBefore !== null) transactionData.bonusBalanceBefore = bonusBalanceBefore;
        if (bonusBalanceAfter !== null) transactionData.bonusBalanceAfter = bonusBalanceAfter;

        const transaction = new Transaction(transactionData);
        await transaction.save();
        console.log(`Transação registrada: ${type} para usuário ${userId}, valor ${amount} ${currency}`);
    } catch (error) {
        console.error(`Erro ao registrar transação (${type}) para usuário ${userId}:`, error);
        // Não parar a execução principal por erro de log de transação, mas registrar o erro
    }
}

// Função para enviar notificações
async function createNotification(userId, title, message, type = 'info', displayType = 'alert', actionUrl = null, actionText = null, isGlobal = false, fullMessage = null) {
    try {
        const notification = new Notification({
            user: isGlobal ? null : userId,
            title,
            message,
            fullMessage: fullMessage || message,
            type,
            displayType,
            actionUrl,
            actionText,
            isGlobal
        });
        await notification.save();
        console.log(`Notificação criada: "${title}" para ${isGlobal ? 'GLOBAL' : 'usuário ' + userId}`);
        // Aqui você poderia integrar com WebSockets para enviar em tempo real, se desejado
    } catch (error) {
        console.error('Erro ao criar notificação:', error);
    }
}
// ==========================================================================
// PARTE 2: ROTAS DE AUTENTICAÇÃO E CONFIGURAÇÃO
// ==========================================================================

// (Continuação da Parte 1: Imports, Configuração, Modelos, Middlewares, Utilitários)
// ... (Todo o código da Parte 1 vai aqui acima) ...


// --- Router Principal da API ---
const apiRouter = express.Router();


// ---------- ROTAS DE AUTENTICAÇÃO (/api/auth) ----------

// POST /api/auth/register
apiRouter.post('/auth/register', async (req, res) => {
    const { name, email, password, securityQuestion, securityAnswer, referralCode: inviterReferralCode } = req.body;

    try {
        // Validações básicas
        if (!name || !email || !password || !securityQuestion || !securityAnswer) {
            return res.status(400).json({ success: false, message: 'Por favor, preencha todos os campos obrigatórios.' });
        }
        if (password.length < 6) {
            return res.status(400).json({ success: false, message: 'A senha deve ter no mínimo 6 caracteres.' });
        }
        const emailRegex = /\S+@\S+\.\S+/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'Formato de email inválido.' });
        }

        const userExists = await User.findOne({ email: email.toLowerCase() });
        if (userExists) {
            return res.status(400).json({ success: false, message: 'Este email já está cadastrado.' });
        }

        let inviterUser = null;
        if (inviterReferralCode) {
            inviterUser = await User.findOne({ referralCode: inviterReferralCode });
            if (!inviterUser) {
                console.log(`Código de referência de convite "${inviterReferralCode}" não encontrado.`);
                // Não bloquear cadastro, mas o usuário não será marcado como indicado por ninguém específico
            }
        }
        
        // Gerar código de referência único para o novo usuário
        let newUserReferralCode;
        let isCodeUnique = false;
        let config = await AdminConfig.findOneAndUpdate({}, { $setOnInsert: { configName: "mainConfig" } }, { upsert: true, new: true });
        let suffix = config.nextReferralSuffix || 1001;

        while(!isCodeUnique) {
            newUserReferralCode = generateUserReferralCode(name, suffix);
            const existingCodeUser = await User.findOne({ referralCode: newUserReferralCode });
            if (!existingCodeUser) {
                isCodeUnique = true;
                config.nextReferralSuffix = suffix + 1;
                await config.save();
            } else {
                suffix++; // Tenta o próximo sufixo
            }
        }

        const user = new User({
            name,
            email: email.toLowerCase(),
            password,
            securityQuestion,
            securityAnswer,
            referralCode: newUserReferralCode,
            referredBy: inviterUser ? inviterUser._id : null,
            balance: 200 // Bônus inicial
        });
        const savedUser = await user.save();

        // Registrar transação de bônus de cadastro
        await recordTransaction(savedUser._id, 'bonus_signup', 200, 'MT', 'Bônus de cadastro inicial', 'Completed');

        // Se foi indicado e o referrer existe, registrar na ReferralHistory
        if (inviterUser) {
            const referralEntry = new ReferralHistory({
                referrer: inviterUser._id,
                referredUser: savedUser._id,
                status: 'PendingValidation'
            });
            await referralEntry.save();
             // Notificar o referrer (opcional)
            await createNotification(inviterUser._id, 'Novo Indicado!', `${savedUser.name} cadastrou-se usando seu link. Bônus pendente de validação.`);
        }

        // Notificar o novo usuário
        await createNotification(savedUser._id, 'Bem-vindo à InvestElite!', 'Sua conta foi criada e você recebeu 200 MT de bônus!', 'success', 'alert', '/dashboard.html', 'Ir para o Painel');

        res.status(201).json({
            success: true,
            message: 'Usuário cadastrado com sucesso! Você recebeu 200 MT de bônus.',
            user: { id: savedUser._id, name: savedUser.name, email: savedUser.email, referralCode: savedUser.referralCode }
        });

    } catch (error) {
        console.error('Erro no registro:', error);
        // Tratar erros de validação do Mongoose
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(val => val.message);
            return res.status(400).json({ success: false, message: messages.join('. ') });
        }
        res.status(500).json({ success: false, message: 'Erro no servidor ao registrar usuário.' });
    }
});


// POST /api/auth/login
apiRouter.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Por favor, forneça email e senha.' });
        }
        const user = await User.findOne({ email: email.toLowerCase() });

        if (user && (await user.matchPassword(password))) {
            if (user.isBlocked) {
                return res.status(403).json({ success: false, message: 'Sua conta está bloqueada. Entre em contato com o suporte.' });
            }

            const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
                expiresIn: '7d',
            });

            // Atualizar lastLogin (opcional, pode adicionar um campo no UserSchema)
            // user.lastLogin = new Date();
            // await user.save();

            res.json({
                success: true,
                message: 'Login bem-sucedido!',
                token,
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                },
            });
        } else {
            res.status(401).json({ success: false, message: 'Email ou senha inválidos.' });
        }
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ success: false, message: 'Erro no servidor ao fazer login.' });
    }
});


// POST /api/auth/forgot-password-request (Recuperação de senha - passo 1: verificar pergunta)
// O front-end não tem um fluxo para isso ainda, mas é uma base
apiRouter.post('/auth/forgot-password-request', async (req, res) => {
    const { email, securityAnswer } = req.body;
    try {
        if (!email || !securityAnswer) {
            return res.status(400).json({ success: false, message: "Email e resposta de segurança são obrigatórios." });
        }
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({ success: false, message: "Usuário não encontrado." });
        }
        if (await user.matchSecurityAnswer(securityAnswer)) {
            // Resposta correta. Gerar um token de reset temporário.
            // Este token NÃO é o JWT de login. É um token específico para reset de senha.
            const resetToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '15m' }); // Token curto
            // Não enviar o token diretamente. O front-end atual pede para contatar o admin.
            // Se fosse um fluxo automático, aqui enviaria email com link contendo o token.
            // Por agora, apenas confirmamos que a resposta está correta.
            res.json({ success: true, message: "Resposta de segurança correta. Por favor, contate o administrador para os próximos passos." });
        } else {
            res.status(401).json({ success: false, message: "Resposta de segurança incorreta." });
        }
    } catch (error) {
        console.error("Erro na solicitação de recuperação de senha:", error);
        res.status(500).json({ success: false, message: "Erro no servidor." });
    }
});

// POST /api/auth/reset-password (Recuperação de senha - passo 2: definir nova senha com token de reset)
// Esta rota seria usada pelo admin ou por um link de email seguro
apiRouter.post('/auth/reset-password', async (req, res) => {
    const { resetToken, newPassword } = req.body;
    try {
        if(!resetToken || !newPassword) {
            return res.status(400).json({ success: false, message: "Token e nova senha são obrigatórios." });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ success: false, message: "Nova senha deve ter no mínimo 6 caracteres." });
        }

        const decoded = jwt.verify(resetToken, JWT_SECRET); // Verifica o token de reset
        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ success: false, message: "Usuário não encontrado ou token inválido." });
        }

        user.password = newPassword; // O hook pre('save') vai hashear
        await user.save();

        await createNotification(user._id, 'Senha Alterada', 'Sua senha foi alterada com sucesso através da recuperação de conta.', 'success');
        res.json({ success: true, message: "Senha alterada com sucesso." });

    } catch (error) {
        console.error("Erro ao resetar senha:", error);
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, message: "Token de reset inválido ou expirado." });
        }
        res.status(500).json({ success: false, message: "Erro no servidor ao resetar senha." });
    }
});


// ---------- ROTAS DE CONFIGURAÇÃO GERAL (/api/config) ----------
// Estas rotas geralmente não precisam de `protect` se forem dados públicos.

// GET /api/config/investment-plans (Lista todos os planos de investimento ativos)
apiRouter.get('/config/investment-plans', async (req, res) => {
    try {
        const plans = await Plan.find({ isActive: true }).sort({ order: 1, value: 1 }); // Ordena por 'order', depois por 'value'
        // Mapeia para o formato esperado pelo front-end (plans_script.js)
        const formattedPlans = plans.map(p => ({
            id: p.planIdentifier, // O front usa 'id' como planIdentifier
            name: p.name,
            value: p.value,
            dailyPercentage: p.dailyPercentage,
            dailyProfitMT: p.dailyProfitMT,
            totalClaims: p.totalClaimsPerDay,
            claimsSplit: p.claimsSplit.map(cs => ({ currency: cs.currency, amount: cs.amount }))
        }));
        res.json(formattedPlans);
    } catch (error) {
        console.error("Erro ao buscar planos de investimento:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar planos de investimento." });
    }
});


// GET /api/config/payment-methods/:type (type pode ser 'deposit' ou 'withdraw')
apiRouter.get('/config/payment-methods/:methodType', async (req, res) => {
    const { methodType } = req.params; // 'deposit' ou 'withdraw'

    if (!['deposit', 'withdraw'].includes(methodType)) {
        return res.status(400).json({ success: false, message: "Tipo de método inválido." });
    }

    try {
        const configDoc = await AdminConfig.findOne({ configName: "mainConfig" });
        if (!configDoc || !configDoc.paymentMethods) {
            return res.json([]);
        }

        const activeMethods = configDoc.paymentMethods
            .filter(pm => methodType === 'deposit' ? pm.isActiveForDeposit : pm.isActiveForWithdrawal)
            .map(pm => ({
                id: pm.methodIdentifier,
                name: pm.name,
                type: pm.type, // 'mobile_money', 'crypto'
                currencyForCrypto: pm.currencyForCrypto, // 'BTC', 'ETH', 'USDT'
                network: pm.network, // 'Bitcoin', 'ERC20', 'TRC20'
                address: pm.address, // O número/carteira para o usuário enviar/receber
                instructionsForUser: pm.instructionsForUser,
                // Para front-end de saque:
                requiresNetwork: pm.type === 'crypto', // Usado no withdraw_script
                feePercentage: pm.withdrawalFeePercentage, // Usado no withdraw_script
                // Para front-end de depósito (se necessário):
                minDeposit: pm.minDeposit,
                // Icon (gerado no front-end, mas pode ser enviado do backend se preferir)
            }));
        res.json(activeMethods);
    } catch (error) {
        console.error(`Erro ao buscar métodos de ${methodType}:`, error);
        res.status(500).json({ success: false, message: `Erro ao buscar métodos de ${methodType}.` });
    }
});

// GET /api/config/site-text/:key (Busca um texto específico do site configurado pelo admin)
apiRouter.get('/config/site-text/:key', async (req, res) => {
    try {
        const { key } = req.params;
        const configDoc = await AdminConfig.findOne({ configName: "mainConfig" });
        if (configDoc && configDoc.siteTexts) {
            const siteText = configDoc.siteTexts.find(st => st.key === key);
            if (siteText) {
                return res.json({ success: true, key: siteText.key, value: siteText.value });
            }
        }
        res.status(404).json({ success: false, message: "Texto não encontrado." });
    } catch (error) {
        console.error("Erro ao buscar texto do site:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar texto do site." });
    }
});


// Montar o router da API no prefixo /api
app.use('/api', apiRouter);


// (A Parte 3 incluirá as rotas de usuário: /api/user/... )
// ======================================================================================
// PARTE 3 (CONSOLIDADA): ROTAS DO USUÁRIO - PROTEGIDAS COM JWT
// ======================================================================================

// (Continuação da Parte 1 e Parte 2)
// ... (Todo o código da Parte 1: Imports, Config, Modelos, Middlewares, Utilitários) ...
// ... (Todo o código da Parte 2: Rotas /api/auth e /api/config) ...
// Lembre-se que 'apiRouter' foi definido na Parte 2 e está sendo usado aqui.

// ---------- ROTAS DO USUÁRIO (/api/user) ----------
// Todas as rotas aqui dentro usarão o middleware `protect`

// GET /api/user/dashboard-data
apiRouter.get('/user/dashboard-data', protect, async (req, res) => {
    try {
        const userId = req.user._id;
        const user = await User.findById(userId).populate('activePlanId');

        if (!user) {
            return res.status(404).json({ success: false, message: "Usuário não encontrado." });
        }

        const userInfo = { name: user.name, email: user.email, referralCode: user.referralCode };
        const balances = {
            total: user.balance + user.bonusBalance,
            available: user.balance,
            invested: user.totalInvested, // Este campo precisará ser atualizado quando um plano é ativado
            bonus: user.bonusBalance,
        };

        let activePlansData = [];
        if (user.activePlanId) {
            const plan = user.activePlanId;
            const todayStr = new Date().toISOString().split('T')[0];
            let claimsMadeTodayCount = 0;
            if (user.lastClaimResetDate === todayStr) {
                 claimsMadeTodayCount = user.dailyClaims.length;
            }
            // Reset de claims (ver nota sobre cron job na versão anterior)

            const claimsData = plan.claimsSplit.map((split, index) => {
                const hasClaimedThis = user.dailyClaims.find(dc => dc.claimIndex === index);
                return {
                    id: `claim_${plan.planIdentifier}_${index}`,
                    currency: split.currency,
                    amount: split.amount,
                    claimed: !!hasClaimedThis
                };
            });

            const now = new Date();
            const endOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999);
            const nextResetTimestamp = Math.floor(endOfDay.getTime() / 1000);

            activePlansData.push({
                id: plan.planIdentifier,
                name: plan.name,
                investmentValue: plan.value,
                dailyProfit: plan.dailyProfitMT,
                dailyPercentage: plan.dailyPercentage,
                nextResetTimestamp: nextResetTimestamp,
                totalClaimsPerDay: plan.totalClaimsPerDay,
                claimsMadeToday: claimsMadeTodayCount,
                claims: claimsData
            });
        }

        const recentClaimsTransactions = await Transaction.find({ user: userId, type: 'claim_income' })
            .sort({ createdAt: -1 })
            .limit(5);
        const recentClaims = recentClaimsTransactions.map(tx => ({
            timestamp: tx.createdAt,
            amount: tx.amount,
            currency: tx.currency,
            planName: tx.description.includes("Plano") ? tx.description.substring(tx.description.indexOf("do ") + 3) : "Rendimento",
            status: tx.status || "Concluído"
        }));

        const notifications = await Notification.find({
            $or: [{ user: userId, read: false }, { isGlobal: true, user: null /* Lógica p/ não repetir lidas globais */ }]
        }).sort({ createdAt: -1 }).limit(10);

        const referralStats = await ReferralHistory.aggregate([
            { $match: { referrer: userId } },
            {
                $group: {
                    _id: "$referrer",
                    totalReferred: { $sum: 1 },
                    validReferred: { $sum: { $cond: [{ $in: ["$status", ["BonusAwardedToBonusBalance", "BonusReleasedToMainBalance"]] }, 1, 0] } },
                }
            }
        ]);
        const referralsSummary = referralStats.length > 0 ? referralStats[0] : { totalReferred: 0, validReferred: 0 };

        res.json({
            success: true, user: userInfo, balances, activePlans: activePlansData, recentClaims,
            notifications: notifications.map(n => ({
                id: n._id, title: n.title, message: n.message, fullMessage: n.fullMessage,
                timestamp: n.createdAt, read: n.read, actionUrl: n.actionUrl, actionText: n.actionText
            })),
            referrals: { activeCount: referralsSummary.validReferred }
        });

    } catch (error) {
        console.error("Erro dashboard-data:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar dados do dashboard." });
    }
});


// POST /api/user/plans/:planIdentifier/claims/:claimDetailId
apiRouter.post('/user/plans/:planIdentifier/claims/:claimDetailId', protect, async (req, res) => {
    const userId = req.user._id;
    const { planIdentifier, claimDetailId } = req.params;

    try {
        const user = await User.findById(userId).populate('activePlanId');
        if (!user || !user.activePlanId || user.activePlanId.planIdentifier !== planIdentifier) {
            return res.status(400).json({ success: false, message: "Plano ativo inválido para este claim." });
        }

        const plan = user.activePlanId;
        const claimIndex = parseInt(claimDetailId.split('_').pop(), 10);

        if (isNaN(claimIndex) || claimIndex < 0 || claimIndex >= plan.claimsSplit.length) {
            return res.status(400).json({ success: false, message: "Índice de claim inválido." });
        }

        const todayStr = new Date().toISOString().split('T')[0];
        if (user.lastClaimResetDate !== todayStr) {
            user.dailyClaims = [];
            user.lastClaimResetDate = todayStr;
        }

        if (user.dailyClaims.length >= plan.totalClaimsPerDay) {
            return res.status(400).json({ success: false, message: "Limite de claims diários atingido." });
        }
        if (user.dailyClaims.find(dc => dc.claimIndex === claimIndex)) {
            return res.status(400).json({ success: false, message: "Este claim específico já foi realizado hoje." });
        }

        const claimToMake = plan.claimsSplit[claimIndex];
        if (!claimToMake) return res.status(400).json({ success: false, message: "Detalhe do claim não encontrado." });

        const oldBalance = user.balance; // Saldo principal
        // Lógica de crédito do claim:
        if (claimToMake.currency === 'MT') {
            user.balance += claimToMake.amount;
        } else {
            // Para cripto, idealmente adicionar a um saldo de cripto específico.
            // Por ora, apenas notificar e registrar a transação. O admin creditaria manualmente ou um sistema futuro.
            await createNotification(userId, `Claim de ${claimToMake.currency}`, `Você coletou ${claimToMake.amount} ${claimToMake.currency}.`, 'success');
        }

        user.dailyClaims.push({ claimIndex, currency: claimToMake.currency, amount: claimToMake.amount, claimedAt: new Date() });
        await user.save();

        await recordTransaction(userId, 'claim_income', claimToMake.amount, claimToMake.currency,
            `Claim ${claimIndex + 1}/${plan.totalClaimsPerDay} do ${plan.name}`, 'Completed',
            { id: plan._id, model: 'Plan' },
            claimToMake.currency === 'MT' ? oldBalance : null,
            claimToMake.currency === 'MT' ? user.balance : null
        );

        res.json({
            success: true, message: `Claim de ${claimToMake.amount} ${claimToMake.currency} realizado!`,
            newBalance: user.balance, claimsMadeToday: user.dailyClaims.length, dailyClaimsDetails: user.dailyClaims
        });

    } catch (error) {
        console.error("Erro ao processar claim:", error);
        res.status(500).json({ success: false, message: "Erro no servidor ao processar claim." });
    }
});


// PATCH /api/user/notifications/:notificationId/read
apiRouter.patch('/user/notifications/:notificationId/read', protect, async (req, res) => {
    try {
        const notification = await Notification.findOneAndUpdate(
            { _id: req.params.notificationId, user: req.user._id }, { read: true }, { new: true }
        );
        if (!notification) {
            const globalNotification = await Notification.findOne({ _id: req.params.notificationId, isGlobal: true });
            if (globalNotification) return res.json({ success: true, message: "Notificação global visualizada." });
            return res.status(404).json({ success: false, message: "Notificação não encontrada." });
        }
        res.json({ success: true, message: "Notificação marcada como lida.", notification });
    } catch (error) {
        console.error("Erro ao marcar notificação:", error);
        res.status(500).json({ success: false, message: "Erro no servidor." });
    }
});


// POST /api/user/deposits
apiRouter.post('/user/deposits', protect, async (req, res) => {
    const { amount, methodId, transaction_id_user, planId: planToActivateIdentifier } = req.body;
    const userId = req.user._id;

    try {
        const parsedAmount = parseFloat(amount);
        if (isNaN(parsedAmount) || parsedAmount < 50) {
            return res.status(400).json({ success: false, message: "Valor do depósito deve ser no mínimo 50 MT." });
        }
        if (!methodId || !transaction_id_user) {
            return res.status(400).json({ success: false, message: "Método e ID da transação são obrigatórios." });
        }

        const configDoc = await AdminConfig.findOne({ configName: "mainConfig" });
        const paymentMethod = configDoc?.paymentMethods.find(pm => pm.methodIdentifier === methodId && pm.isActiveForDeposit);
        if (!paymentMethod) return res.status(400).json({ success: false, message: "Método de pagamento inválido." });
        if (parsedAmount < paymentMethod.minDeposit) {
             return res.status(400).json({ success: false, message: `Mínimo para ${paymentMethod.name} é ${paymentMethod.minDeposit} MT.` });
        }

        let planToActivateDocId = null;
        if (planToActivateIdentifier) {
            const plan = await Plan.findOne({ planIdentifier: planToActivateIdentifier, isActive: true });
            if (!plan) return res.status(400).json({ success: false, message: "Plano selecionado inválido." });
            // Opcional: if (parsedAmount !== plan.value) { /* erro */ }
            planToActivateDocId = plan._id;
        }

        const deposit = new Deposit({
            user: userId, amount: parsedAmount, currency: 'MT', methodId: paymentMethod.methodIdentifier,
            methodName: paymentMethod.name, transactionIdUser: transaction_id_user,
            planToActivate: planToActivateDocId, status: 'Pending'
        });
        await deposit.save();

        await createNotification(null, `Depósito Pendente #${deposit._id.toString().slice(-6)}`,
            `${req.user.name} enviou comprovante de ${parsedAmount} MT via ${paymentMethod.name}.`,
            'info', 'alert', '/admin/deposits', 'Ver Depósitos', true);

        await recordTransaction(userId, 'deposit', parsedAmount, 'MT', `Depósito via ${paymentMethod.name}`, 'Pending', {id: deposit._id, model: 'Deposit'});

        res.status(201).json({
            success: true, message: "Comprovante de depósito enviado. Aguardando aprovação.",
            deposit: { id: deposit._id, amount: deposit.amount, method: deposit.methodName, status: deposit.status, date: deposit.createdAt }
        });

    } catch (error) {
        console.error("Erro ao criar depósito:", error);
        if (error.name === 'ValidationError') return res.status(400).json({ success: false, message: Object.values(error.errors).map(e => e.message).join(', ') });
        res.status(500).json({ success: false, message: "Erro no servidor ao processar depósito." });
    }
});

// GET /api/user/deposits/history
apiRouter.get('/user/deposits/history', protect, async (req, res) => {
    try {
        const deposits = await Deposit.find({ user: req.user._id })
            .sort({ createdAt: -1 })
            .select('amount currency methodName status createdAt planToActivate')
            .populate('planToActivate', 'name');
        res.json(deposits.map(dep => ({
            id: dep._id, date: dep.createdAt, amount: dep.amount, currency: dep.currency,
            method: dep.methodName, status: dep.status, planActivated: dep.planToActivate ? dep.planToActivate.name : null
        })));
    } catch (error) {
        console.error("Erro histórico de depósitos:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar histórico de depósitos." });
    }
});

const USER_MIN_WITHDRAWAL = 50;
const USER_MAX_WITHDRAWAL = 50000;

// GET /api/user/withdraw-info
apiRouter.get('/user/withdraw-info', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) return res.status(404).json({ success: false, message: "Usuário não encontrado."});
        res.json({
            success: true, withdrawableBalance: user.balance,
            isEligibleForWithdrawal: user.firstDepositMade
        });
    } catch (error) {
        console.error("Erro withdraw-info:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar informações de saque." });
    }
});

// POST /api/user/withdrawals
apiRouter.post('/user/withdrawals', protect, async (req, res) => {
    const { amount, methodId, recipientAddress } = req.body;
    const userId = req.user._id;

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: "Usuário não encontrado." });
        if (!user.firstDepositMade) return res.status(403).json({ success: false, message: "Realize um depósito antes de sacar." });

        const requestedAmount = parseFloat(amount);
        if (isNaN(requestedAmount) || requestedAmount < USER_MIN_WITHDRAWAL || requestedAmount > USER_MAX_WITHDRAWAL) {
            return res.status(400).json({ success: false, message: `Valor do saque entre ${USER_MIN_WITHDRAWAL} e ${USER_MAX_WITHDRAWAL} MT.` });
        }
        if (requestedAmount > user.balance) return res.status(400).json({ success: false, message: "Saldo insuficiente." });
        if (!methodId || !recipientAddress) return res.status(400).json({ success: false, message: "Método e endereço/número são obrigatórios." });

        const configDoc = await AdminConfig.findOne({ configName: "mainConfig" });
        const paymentMethod = configDoc?.paymentMethods.find(pm => pm.methodIdentifier === methodId && pm.isActiveForWithdrawal);
        if (!paymentMethod) return res.status(400).json({ success: false, message: "Método de recebimento inválido." });
        if (requestedAmount < paymentMethod.minWithdrawal) {
            return res.status(400).json({ success: false, message: `Mínimo para ${paymentMethod.name} é ${paymentMethod.minWithdrawal} MT.` });
        }

        const feePercentage = paymentMethod.withdrawalFeePercentage / 100;
        const feeAmount = parseFloat((requestedAmount * feePercentage).toFixed(2));
        const amountToReceive = parseFloat((requestedAmount - feeAmount).toFixed(2));

        const balanceBefore = user.balance;
        user.balance -= requestedAmount;
        await user.save();

        const withdrawal = new Withdrawal({
            user: userId, amountRequested, feePercentage: paymentMethod.withdrawalFeePercentage, feeAmount, amountToReceive,
            methodId: paymentMethod.methodIdentifier, methodName: paymentMethod.name, recipientAddress, status: 'Pending'
        });
        await withdrawal.save();

        await recordTransaction(userId, 'withdrawal', -Math.abs(requestedAmount), 'MT', `Pedido de saque para ${paymentMethod.name}`, 'Pending', {id: withdrawal._id, model: 'Withdrawal'}, balanceBefore, user.balance);

        await createNotification(null, `Pedido de Saque #${withdrawal._id.toString().slice(-6)}`,
            `${user.name} solicitou saque de ${requestedAmount} MT para ${paymentMethod.name}.`,
            'info', 'alert', '/admin/withdrawals', 'Ver Saques', true);

        res.status(201).json({
            success: true, message: "Pedido de saque enviado. Aguardando aprovação.",
            withdrawal: { id: withdrawal._id, amountRequested, amountToReceive, method: withdrawal.methodName, status: 'Pending', date: withdrawal.createdAt },
            newBalance: user.balance
        });

    } catch (error) {
        console.error("Erro ao criar saque:", error);
        res.status(500).json({ success: false, message: "Erro no servidor ao processar saque." });
    }
});

// GET /api/user/withdrawals/history
apiRouter.get('/user/withdrawals/history', protect, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ user: req.user._id })
            .sort({ createdAt: -1 })
            .select('amountRequested amountToReceive methodName status createdAt recipientAddress transactionHashAdmin');
        res.json(withdrawals.map(wd => ({
            id: wd._id, date: wd.createdAt, amountRequested: wd.amountRequested, amountReceived: wd.amountToReceive,
            currency: 'MT', method: wd.methodName, status: wd.status,
            recipient: wd.recipientAddress, adminTxHash: wd.transactionHashAdmin
        })));
    } catch (error) {
        console.error("Erro histórico de saques:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar histórico de saques." });
    }
});


// ... (outras partes do seu server.js) ...

// (Dentro de apiRouter ou app, dependendo de como você estruturou)

// GET /api/user/referrals
apiRouter.get('/user/referrals', protect, async (req, res) => { // Certifique-se que 'protect' está aqui
    const userId = req.user._id;
    try {
        const user = await User.findById(userId).select('referralCode balance bonusBalance firstDepositMade');
        if (!user) {
            return res.status(404).json({ success: false, message: "Usuário não encontrado." });
        }

        // ===== MODIFICAÇÃO AQUI =====
        const frontendBaseUrl = process.env.FRONTEND_BASE_URL;
        if (!frontendBaseUrl) {
            console.warn("AVISO: FRONTEND_BASE_URL não está definido no .env. O link de referência pode não funcionar corretamente.");
            // Você pode optar por um fallback ou retornar um erro se for crítico
        }
        // Assumindo que sua página de registro no frontend é 'register.html' na raiz
        // Se for diferente, ajuste o caminho (ex: '/auth/register.html' ou apenas '/')
        const referralLink = `${frontendBaseUrl || 'https://cripto-moz1.netlify.app'}/register.html?ref=${user.referralCode}`;
        // Adicionei um fallback direto para sua URL caso process.env falhe por algum motivo no deploy inicial,
        // mas o ideal é que process.env.FRONTEND_BASE_URL funcione.

        const referrals = await ReferralHistory.find({ referrer: userId })
            .populate('referredUser', 'name email createdAt isBlocked')
            .sort({ createdAt: -1 });

        let totalBonusAwarded = 0;
        referrals.forEach(r => {
            if (r.status === 'BonusAwardedToBonusBalance' || r.status === 'BonusReleasedToMainBalance') {
                totalBonusAwarded += r.bonusAmount;
            }
        });

        const availableBonusForWithdrawal = user.firstDepositMade ? user.bonusBalance : 0;

        const formattedReferredUsers = referrals.map(r => {
            let referredUserName = 'Usuário Deletado';
            if (r.referredUser) {
                referredUserName = r.referredUser.name ? r.referredUser.name.substring(0,3) + '***' : 'Usuário***';
                if (r.referredUser.isBlocked) referredUserName += " (Bloqueado)";
            }
            return {
                id: r.referredUser ? r.referredUser._id : null,
                name: referredUserName,
                date: r.createdAt,
                status: r.status,
                bonusEarned: (r.status === 'BonusAwardedToBonusBalance' || r.status === 'BonusReleasedToMainBalance') ? r.bonusAmount : 0
            };
        });

        res.json({
            success: true,
            referralLink, // Agora com a URL base correta
            stats: {
                totalReferred: referrals.length,
                validReferred: referrals.filter(r => r.status === 'BonusAwardedToBonusBalance' || r.status === 'BonusReleasedToMainBalance').length,
                totalBonus: totalBonusAwarded,
                availableBonus: availableBonusForWithdrawal
            },
            referredUsers: formattedReferredUsers
        });

    } catch (error) {
        console.error("Erro dados de referência:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar dados de referência." });
    }
});

// ... (resto do seu server.js) ...

// GET /api/user/transactions
apiRouter.get('/user/transactions', protect, async (req, res) => {
    const userId = req.user._id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const typeFilter = req.query.type;

    try {
        let query = { user: userId };
        if (typeFilter && typeFilter !== 'all' && transactionTypeDetails[typeFilter]) {
            query.type = typeFilter;
        }

        const totalTransactions = await Transaction.countDocuments(query);
        const totalPages = Math.ceil(totalTransactions / limit);
        const transactions = await Transaction.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit);
            res.json({
            success: true,
            transactions: transactions.map(tx => ({
                id: tx._id, date: tx.createdAt, type: tx.type, description: tx.description,
                amount: tx.amount, currency: tx.currency, status: tx.status
            })),
            currentPage: page, totalPages: totalPages, totalTransactions
        });

    } catch (error) {
        console.error("Erro histórico de transações:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar histórico de transações." });
    }
});


// GET /api/user/active-plan
apiRouter.get('/user/active-plan', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).populate('activePlanId', 'planIdentifier name');
        if (!user) return res.status(404).json({ success: false, message: "Usuário não encontrado." });

        if (user.activePlanId) {
            res.json({
                success: true,
                planId: user.activePlanId.planIdentifier, // O front-end usa 'planId' para o identifier
                planName: user.activePlanId.name
            });
        } else {
            res.status(404).json({ success: false, message: "Nenhum plano ativo." }); // Front-end espera 404
        }
    } catch (error) {
        console.error("Erro ao buscar plano ativo:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar plano ativo." });
    }
});
// ======================================================================================
// PARTE 4: ROTAS DE ADMIN, INICIALIZAÇÃO DE DADOS, START DO SERVIDOR
// ======================================================================================

// (Continuação da Parte 1, Parte 2 e Parte 3)
// ... (Todo o código anterior vai aqui acima) ...

// ---------- ROTAS DE ADMINISTRADOR (/api/admin) ----------
// Todas as rotas aqui usarão `protect` e `adminProtect`

// --- Helper para Reset de Claims Diários (chamado pelo cron ou manualmente) ---
async function resetAllUserDailyClaims() {
    const todayStr = new Date().toISOString().split('T')[0];
    try {
        const result = await User.updateMany(
            { lastClaimResetDate: { $ne: todayStr } }, // Apenas usuários que não tiveram reset hoje
            { $set: { dailyClaims: [], lastClaimResetDate: todayStr } }
        );
        console.log(`Claims diários resetados para ${result.modifiedCount} usuários.`);
        return { success: true, modifiedCount: result.modifiedCount };
    } catch (error) {
        console.error("Erro ao resetar claims diários de todos os usuários:", error);
        return { success: false, error };
    }
}
// Rota para Admin acionar reset (para teste ou se cron falhar)
apiRouter.post('/admin/maintenance/reset-all-claims', protect, adminProtect, async (req, res) => {
    const result = await resetAllUserDailyClaims();
    if (result.success) {
        res.json({ success: true, message: `Claims resetados para ${result.modifiedCount} usuários.` });
    } else {
        res.status(500).json({ success: false, message: "Erro ao resetar claims.", error: result.error.message });
    }
});


// --- Gestão de Depósitos (Admin) ---
// GET /api/admin/deposits?status=Pending
apiRouter.get('/admin/deposits', protect, adminProtect, async (req, res) => {
    const { status, page = 1, limit = 10 } = req.query;
    let query = {};
    if (status) query.status = status;

    try {
        const options = {
            page: parseInt(page, 10),
            limit: parseInt(limit, 10),
            sort: { createdAt: -1 },
            populate: [{ path: 'user', select: 'name email referralCode' }, {path: 'planToActivate', select: 'name value'}]
        };
        // Mongoose-Paginate-v2 seria ideal aqui, mas vamos fazer manualmente por simplicidade
        const deposits = await Deposit.find(query)
            .sort(options.sort)
            .skip((options.page - 1) * options.limit)
            .limit(options.limit)
            .populate(options.populate.path, options.populate.select)
            .populate('planToActivate', 'name value'); // Adicionado para mostrar detalhes do plano

        const totalDeposits = await Deposit.countDocuments(query);

        res.json({
            success: true,
            deposits,
            currentPage: options.page,
            totalPages: Math.ceil(totalDeposits / options.limit),
            totalDeposits
        });
    } catch (error) {
        console.error("Admin - Erro ao buscar depósitos:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar depósitos." });
    }
});


// PATCH /api/admin/deposits/:depositId/approve
apiRouter.patch('/admin/deposits/:depositId/approve', protect, adminProtect, async (req, res) => {
    const { depositId } = req.params;
    try {
        const deposit = await Deposit.findById(depositId).populate('user');
        if (!deposit) return res.status(404).json({ success: false, message: "Depósito não encontrado." });
        if (deposit.status !== 'Pending') return res.status(400).json({ success: false, message: "Este depósito não está pendente." });

        const user = deposit.user;
        if (!user) return res.status(404).json({ success: false, message: "Usuário do depósito não encontrado."});

        const balanceBefore = user.balance;
        const bonusBalanceBefore = user.bonusBalance;

        user.balance += deposit.amount;
        deposit.status = 'Confirmed';
        deposit.confirmedAt = new Date();

        let firstDepositTransaction = false;
        if (!user.firstDepositMade) {
            user.firstDepositMade = true;
            firstDepositTransaction = true;
            // Liberar bônus de referência que estavam no bonusBalance para o saldo principal
            if (user.bonusBalance > 0) {
                await recordTransaction(user._id, 'bonus_referral', user.bonusBalance, 'MT', 'Liberação de bônus de referência para saldo principal', 'Completed', {}, balanceBefore, user.balance + user.bonusBalance, bonusBalanceBefore, 0);
                user.balance += user.bonusBalance; // Move bônus para o saldo principal
                user.bonusBalance = 0; // Zera saldo de bônus
            }
        }

        // Ativar plano se o depósito for para um plano específico
        if (deposit.planToActivate) {
            const plan = await Plan.findById(deposit.planToActivate);
            if (plan && plan.isActive) {
                if (user.balance >= plan.value) { // Verifica se tem saldo suficiente (após o depósito)
                    // Se o usuário já tem um plano, a lógica de "upgrade" ou substituição entraria aqui.
                    // Por simplicidade, vamos assumir que pode ter apenas um.
                    user.activePlanId = plan._id;
                    user.activePlanActivationDate = new Date();
                    user.totalInvested += plan.value; // Adiciona ao total investido
                    user.balance -= plan.value; // Deduz do saldo principal para o investimento
                    user.dailyClaims = []; // Reseta claims para o novo plano
                    user.lastClaimResetDate = new Date().toISOString().split('T')[0];

                    await recordTransaction(user._id, 'plan_activation', -Math.abs(plan.value), 'MT', `Ativação do ${plan.name}`, 'Completed', {id: plan._id, model: 'Plan'}, balanceBefore, user.balance);
                    deposit.adminNotes = (deposit.adminNotes || "") + ` Plano ${plan.name} ativado.`;
                    await createNotification(user._id, `Plano ${plan.name} Ativado!`, `Seu investimento no ${plan.name} de ${formatCurrency(plan.value)} foi ativado.`, 'success');
                } else {
                    deposit.adminNotes = (deposit.adminNotes || "") + ` Saldo insuficiente para ativar ${plan.name} após depósito.`;
                     await createNotification(user._id, `Falha na Ativação do Plano`, `Seu depósito foi confirmado, mas o saldo não foi suficiente para ativar o plano ${plan.name}. Contate o suporte.`, 'warning');
                }
            } else {
                 deposit.adminNotes = (deposit.adminNotes || "") + ` Plano ${deposit.planToActivate.name} não pôde ser ativado (inativo/não encontrado).`;
            }
        }
        
        await user.save();
        await deposit.save();

        await recordTransaction(user._id, 'deposit', deposit.amount, deposit.currency, `Depósito via ${deposit.methodName} confirmado`, 'Completed', {id: deposit._id, model: 'Deposit'}, balanceBefore, user.balance, bonusBalanceBefore, user.bonusBalance);

        await createNotification(user._id, 'Depósito Confirmado', `Seu depósito de ${formatCurrency(deposit.amount, deposit.currency)} foi confirmado.`, 'success');

        // Lógica para bônus de quem indicou este usuário (referrer)
        if (firstDepositTransaction && user.referredBy) {
            const referrer = await User.findById(user.referredBy);
            const referralRecord = await ReferralHistory.findOne({ referrer: referrer._id, referredUser: user._id });
            if (referrer && referralRecord && referralRecord.status === 'PendingValidation') {
                const bonusAmount = referralRecord.bonusAmount;
                const referrerBonusBalanceBefore = referrer.bonusBalance;
                referrer.bonusBalance += bonusAmount;
                referralRecord.status = 'BonusAwardedToBonusBalance';
                referralRecord.awardedAt = new Date();
                await referrer.save();
                await referralRecord.save();
                await recordTransaction(referrer._id, 'bonus_referral', bonusAmount, 'MT', `Bônus de referência por ${user.name}`, 'Completed', { id: user._id, model: 'User' }, null, null, referrerBonusBalanceBefore, referrer.bonusBalance);
                await createNotification(referrer._id, 'Bônus de Referência Recebido!', `Você recebeu ${bonusAmount} MT de bônus por indicar ${user.name}.`, 'success');
            }
        }

        res.json({ success: true, message: "Depósito aprovado e saldo do usuário atualizado.", deposit });

    } catch (error) {
        console.error("Admin - Erro ao aprovar depósito:", error);
        res.status(500).json({ success: false, message: "Erro ao aprovar depósito." });
    }
});

// PATCH /api/admin/deposits/:depositId/reject
apiRouter.patch('/admin/deposits/:depositId/reject', protect, adminProtect, async (req, res) => {
    const { depositId } = req.params;
    const { reason } = req.body; // Admin pode fornecer uma razão
    try {
        const deposit = await Deposit.findById(depositId);
        if (!deposit) return res.status(404).json({ success: false, message: "Depósito não encontrado." });
        if (deposit.status !== 'Pending') return res.status(400).json({ success: false, message: "Este depósito não está pendente." });

        deposit.status = 'Rejected';
        deposit.adminNotes = reason || "Rejeitado pelo administrador.";
        await deposit.save();

        // Atualizar transação associada para 'Failed' ou 'Rejected'
        await Transaction.findOneAndUpdate(
            { 'relatedRecord.recordId': deposit._id, 'relatedRecord.recordModel': 'Deposit', type: 'deposit' },
            { status: 'Rejected', description: (await Transaction.findOne({ 'relatedRecord.recordId': deposit._id})).description + ` (Rejeitado: ${reason || 'Sem motivo'})`}
        );

        await createNotification(deposit.user, 'Depósito Rejeitado', `Seu depósito de ${formatCurrency(deposit.amount, deposit.currency)} foi rejeitado. Motivo: ${deposit.adminNotes}`, 'error');
        res.json({ success: true, message: "Depósito rejeitado.", deposit });
    } catch (error) {
        console.error("Admin - Erro ao rejeitar depósito:", error);
        res.status(500).json({ success: false, message: "Erro ao rejeitar depósito." });
    }
});


// --- Gestão de Saques (Admin) ---
// GET /api/admin/withdrawals?status=Pending
apiRouter.get('/admin/withdrawals', protect, adminProtect, async (req, res) => {
    const { status, page = 1, limit = 10 } = req.query;
    let query = {};
    if (status) query.status = status;
    try {
        const options = { page: parseInt(page, 10), limit: parseInt(limit, 10), sort: { createdAt: -1 }, populate: { path: 'user', select: 'name email balance' }};
        const withdrawals = await Withdrawal.find(query).sort(options.sort).skip((options.page - 1) * options.limit).limit(options.limit).populate(options.populate.path, options.populate.select);
        const totalWithdrawals = await Withdrawal.countDocuments(query);
        res.json({ success: true, withdrawals, currentPage: options.page, totalPages: Math.ceil(totalWithdrawals / options.limit), totalWithdrawals });
    } catch (error) {
        console.error("Admin - Erro ao buscar saques:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar saques." });
    }
});

// PATCH /api/admin/withdrawals/:withdrawalId/process
apiRouter.patch('/admin/withdrawals/:withdrawalId/process', protect, adminProtect, async (req, res) => {
    const { withdrawalId } = req.params;
    const { transactionHashAdmin, notes } = req.body; // Admin insere o hash da transação de envio
    try {
        const withdrawal = await Withdrawal.findById(withdrawalId).populate('user');
        if (!withdrawal) return res.status(404).json({ success: false, message: "Pedido de saque não encontrado." });
        if (withdrawal.status !== 'Pending' && withdrawal.status !== 'Processing') {
            return res.status(400).json({ success: false, message: `Saque já está ${withdrawal.status}.` });
        }

        withdrawal.status = 'Completed'; // Ou 'Processing' se for um passo intermediário
        withdrawal.processedAt = new Date();
        if (transactionHashAdmin) withdrawal.transactionHashAdmin = transactionHashAdmin;
        if (notes) withdrawal.adminNotes = (withdrawal.adminNotes || "") + ` Processado: ${notes}`;
        await withdrawal.save();

        // Atualizar transação associada
        await Transaction.findOneAndUpdate(
             { 'relatedRecord.recordId': withdrawal._id, 'relatedRecord.recordModel': 'Withdrawal', type: 'withdrawal' },
             { status: 'Completed' }
        );

        await createNotification(withdrawal.user._id, 'Saque Processado', `Seu saque de ${formatCurrency(withdrawal.amountRequested)} foi processado e enviado.`, 'success');
        res.json({ success: true, message: "Saque processado com sucesso.", withdrawal });
    } catch (error) {
        console.error("Admin - Erro ao processar saque:", error);
        res.status(500).json({ success: false, message: "Erro ao processar saque." });
    }
});

// PATCH /api/admin/withdrawals/:withdrawalId/reject
apiRouter.patch('/admin/withdrawals/:withdrawalId/reject', protect, adminProtect, async (req, res) => {
    const { withdrawalId } = req.params;
    const { reason } = req.body;
    try {
        const withdrawal = await Withdrawal.findById(withdrawalId).populate('user');
        if (!withdrawal) return res.status(404).json({ success: false, message: "Pedido de saque não encontrado." });
        if (withdrawal.status !== 'Pending' && withdrawal.status !== 'Processing') {
             return res.status(400).json({ success: false, message: `Saque já está ${withdrawal.status}.` });
        }

        const user = withdrawal.user;
        // Reverter o valor para o saldo do usuário
        const balanceBeforeReversal = user.balance;
        user.balance += withdrawal.amountRequested; // Devolve o valor total que foi debitado
        await user.save();

        withdrawal.status = 'Rejected';
        withdrawal.adminNotes = reason || "Rejeitado pelo administrador.";
        await withdrawal.save();
        
        // Atualizar transação associada
        await Transaction.findOneAndUpdate(
             { 'relatedRecord.recordId': withdrawal._id, 'relatedRecord.recordModel': 'Withdrawal', type: 'withdrawal' },
             { status: 'Rejected', description: (await Transaction.findOne({ 'relatedRecord.recordId': withdrawal._id})).description + ` (Rejeitado: ${reason || 'Sem motivo'})`}
        );
        // Registrar uma transação de crédito pela reversão
        await recordTransaction(user._id, 'admin_credit', withdrawal.amountRequested, 'MT', `Reversão de saque #${withdrawalId.slice(-6)} rejeitado`, 'Completed', {id: withdrawal._id, model: 'Withdrawal'}, balanceBeforeReversal, user.balance);


        await createNotification(user._id, 'Saque Rejeitado', `Seu pedido de saque de ${formatCurrency(withdrawal.amountRequested)} foi rejeitado. Motivo: ${withdrawal.adminNotes}. O valor foi estornado ao seu saldo.`, 'error');
        res.json({ success: true, message: "Pedido de saque rejeitado e valor estornado.", withdrawal });
    } catch (error) {
        console.error("Admin - Erro ao rejeitar saque:", error);
        res.status(500).json({ success: false, message: "Erro ao rejeitar saque." });
    }
});


// --- Gestão de Usuários (Admin) ---
// GET /api/admin/users
apiRouter.get('/admin/users', protect, adminProtect, async (req, res) => {
    const { page = 1, limit = 10, search = '' } = req.query;
    let query = {};
    if (search) {
        query = { $or: [{ name: { $regex: search, $options: 'i' } }, { email: { $regex: search, $options: 'i' } }, { referralCode: { $regex: search, $options: 'i' } }] };
    }
    try {
        const users = await User.find(query)
            .select('-password -securityAnswer -securityQuestion') // Não enviar campos sensíveis
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .populate('activePlanId', 'name')
            .populate('referredBy', 'name email');
        const totalUsers = await User.countDocuments(query);
        res.json({ success: true, users, currentPage: parseInt(page), totalPages: Math.ceil(totalUsers / limit), totalUsers });
    } catch (error) {
        res.status(500).json({ success: false, message: "Erro ao buscar usuários." });
    }
});

// PATCH /api/admin/users/:userId/toggle-block
apiRouter.patch('/admin/users/:userId/toggle-block', protect, adminProtect, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ success: false, message: "Usuário não encontrado." });
        if (user.role === 'admin') return res.status(403).json({ success: false, message: "Não é possível bloquear um administrador." });

        user.isBlocked = !user.isBlocked;
        await user.save();
        await createNotification(user._id, `Status da Conta Alterado`, `Sua conta foi ${user.isBlocked ? 'BLOQUEADA' : 'DESBLOQUEADA'} pelo administrador.`, user.isBlocked ? 'error' : 'success');
        res.json({ success: true, message: `Usuário ${user.isBlocked ? 'bloqueado' : 'desbloqueado'}.`, isBlocked: user.isBlocked });
    } catch (error) {
        res.status(500).json({ success: false, message: "Erro ao alterar status do usuário." });
    }
});

// POST /api/admin/users/:userId/assign-plan
apiRouter.post('/admin/users/:userId/assign-plan', protect, adminProtect, async (req, res) => {
    const { planIdentifier } = req.body; // Admin envia o IDENTIFICADOR do plano
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ success: false, message: "Usuário não encontrado." });

        const plan = await Plan.findOne({ planIdentifier: planIdentifier, isActive: true });
        if (!plan) return res.status(404).json({ success: false, message: "Plano não encontrado ou inativo." });

        // Lógica para "pagamento" do plano: pode ser deduzido do saldo, ou ser um bônus, etc.
        // Se for deduzir do saldo:
        // if (user.balance < plan.value) {
        //     return res.status(400).json({ success: false, message: `Usuário não tem saldo (${user.balance} MT) suficiente para o plano ${plan.name} (${plan.value} MT).` });
        // }
        // const balanceBefore = user.balance;
        // user.balance -= plan.value;
        // await recordTransaction(user._id, 'plan_activation', -Math.abs(plan.value), 'MT', `Ativação manual do ${plan.name} pelo Admin`, 'Completed', {id: plan._id, model: 'Plan'}, balanceBefore, user.balance);


        user.activePlanId = plan._id;
        user.activePlanActivationDate = new Date();
        user.totalInvested = plan.value; // Define o total investido para este plano (pode precisar de lógica mais complexa se acumula)
        user.dailyClaims = [];
        user.lastClaimResetDate = new Date().toISOString().split('T')[0];
        await user.save();

        await createNotification(user._id, `Plano ${plan.name} Atribuído`, `O administrador atribuiu o ${plan.name} à sua conta.`, 'success');
        res.json({ success: true, message: `Plano ${plan.name} atribuído ao usuário ${user.name}.` });
    } catch (error) {
        console.error("Erro ao atribuir plano:", error);
        res.status(500).json({ success: false, message: "Erro ao atribuir plano." });
    }
});

// --- Gestão de Configurações (Admin) ---
// GET /api/admin/config (pega todas as configs)
apiRouter.get('/admin/config', protect, adminProtect, async(req, res) => {
    try {
        let config = await AdminConfig.findOne({configName: "mainConfig"});
        if (!config) {
            // Cria configuração padrão se não existir
            config = new AdminConfig({
                configName: "mainConfig",
                paymentMethods: [], // Admin adicionará
                siteTexts: [{key: "welcome_message", value: "Bem-vindo!", locationHint: "User Dashboard"}],
                nextReferralSuffix: 1001
            });
            await config.save();
        }
        res.json({success: true, config});
    } catch (error) {
        res.status(500).json({success: false, message: "Erro ao buscar configurações."});
    }
});

// POST /api/admin/config/payment-methods (Adicionar novo método de pagamento)
apiRouter.post('/admin/config/payment-methods', protect, adminProtect, async (req, res) => {
    const { methodIdentifier, name, type, currencyForCrypto, network, address, instructionsForUser, isActiveForDeposit, isActiveForWithdrawal, minDeposit, maxDeposit, minWithdrawal, maxWithdrawal, withdrawalFeePercentage } = req.body;
    try {
        if (!methodIdentifier || !name || !type || !address) {
            return res.status(400).json({ success: false, message: "Identificador, nome, tipo e endereço são obrigatórios."});
        }
        const config = await AdminConfig.findOneAndUpdate(
            { configName: "mainConfig" },
            { $setOnInsert: { configName: "mainConfig" } }, // Garante que o doc exista
            { upsert: true, new: true }
        );

        const existingMethod = config.paymentMethods.find(pm => pm.methodIdentifier === methodIdentifier);
        if (existingMethod) {
            return res.status(400).json({ success: false, message: "Método de pagamento com este identificador já existe."});
        }

        const newMethod = {
            methodIdentifier, name, type, currencyForCrypto, network, address, instructionsForUser,
            isActiveForDeposit: isActiveForDeposit !== undefined ? isActiveForDeposit : true,
            isActiveForWithdrawal: isActiveForWithdrawal !== undefined ? isActiveForWithdrawal : true,
            minDeposit: minDeposit || 50, maxDeposit: maxDeposit || 1000000,
            minWithdrawal: minWithdrawal || 50, maxWithdrawal: maxWithdrawal || 50000,
            withdrawalFeePercentage: withdrawalFeePercentage || 2
        };
        config.paymentMethods.push(newMethod);
        await config.save();
        res.status(201).json({ success: true, message: "Método de pagamento adicionado.", paymentMethod: newMethod });
    } catch (error) {
        console.error("Erro ao adicionar método de pagamento:", error);
        res.status(500).json({ success: false, message: "Erro ao adicionar método de pagamento." });
    }
});
// PATCH /api/admin/config/payment-methods/:methodDbId (Editar método de pagamento existente)
// :methodDbId é o _id do subdocumento paymentMethod
apiRouter.patch('/admin/config/payment-methods/:methodDbId', protect, adminProtect, async (req, res) => {
    const { methodDbId } = req.params;
    const updateData = req.body; // Enviar apenas os campos a serem atualizados

    try {
        const config = await AdminConfig.findOne({ configName: "mainConfig" });
        if (!config) return res.status(404).json({ success: false, message: "Configuração não encontrada." });

        const methodIndex = config.paymentMethods.findIndex(pm => pm._id.toString() === methodDbId);
        if (methodIndex === -1) return res.status(404).json({ success: false, message: "Método de pagamento não encontrado." });

        // Atualizar campos
        Object.keys(updateData).forEach(key => {
            if (key !== '_id' && key !== 'methodIdentifier') { // Não permitir mudar _id ou methodIdentifier aqui
                 config.paymentMethods[methodIndex][key] = updateData[key];
            }
        });
        
        await config.save();
        res.json({ success: true, message: "Método de pagamento atualizado.", paymentMethod: config.paymentMethods[methodIndex] });
    } catch (error) {
         console.error("Erro ao editar método de pagamento:", error);
        res.status(500).json({ success: false, message: "Erro ao editar método de pagamento." });
    }
});

// DELETE /api/admin/config/payment-methods/:methodDbId (Deletar método de pagamento)
apiRouter.delete('/admin/config/payment-methods/:methodDbId', protect, adminProtect, async (req, res) => {
    const { methodDbId } = req.params;
    try {
        const config = await AdminConfig.findOneAndUpdate(
            { configName: "mainConfig" },
            { $pull: { paymentMethods: { _id: methodDbId } } },
            { new: true }
        );
        if (!config) return res.status(404).json({ success: false, message: "Configuração não encontrada." });
        // Verificar se o método foi realmente removido pode ser feito comparando o array antes e depois,
        // ou se a query $pull teve efeito.
        res.json({ success: true, message: "Método de pagamento deletado." });
    } catch (error) {
        res.status(500).json({ success: false, message: "Erro ao deletar método de pagamento." });
    }
});
// --- Gestão de Planos de Investimento (Admin) ---
// POST /api/admin/plans
apiRouter.post('/admin/plans', protect, adminProtect, async (req, res) => {
    const { planIdentifier, name, value, dailyPercentage, dailyProfitMT, totalClaimsPerDay, claimsSplit, order, isActive } = req.body;
    try {
        if (!planIdentifier || !name || !value || !dailyPercentage || !dailyProfitMT || !claimsSplit) {
            return res.status(400).json({ success: false, message: "Campos obrigatórios do plano faltando."});
        }
        const existingPlan = await Plan.findOne({ planIdentifier });
        if (existingPlan) return res.status(400).json({ success: false, message: "Plano com este identificador já existe."});

        const newPlan = new Plan({
            planIdentifier, name, value, dailyPercentage, dailyProfitMT,
            totalClaimsPerDay: totalClaimsPerDay || 5,
            claimsSplit, // Espera [{currency, amount}, ...]
            order: order || 0,
            isActive: isActive !== undefined ? isActive : true
        });
        await newPlan.save();
        res.status(201).json({ success: true, message: "Plano de investimento criado.", plan: newPlan });
    } catch (error) {
        res.status(500).json({ success: false, message: "Erro ao criar plano." });
    }
});

// GET /api/admin/plans (Lista todos os planos, ativos e inativos)
apiRouter.get('/admin/plans', protect, adminProtect, async (req, res) => {
    try {
        const plans = await Plan.find({}).sort({ order: 1, value: 1 });
        res.json({ success: true, plans });
    } catch (error) {
        res.status(500).json({ success: false, message: "Erro ao buscar planos." });
    }
});

// PATCH /api/admin/plans/:planDbId (Editar plano)
apiRouter.patch('/admin/plans/:planDbId', protect, adminProtect, async (req, res) => {
    const { planDbId } = req.params;
    const updateData = req.body;
    try {
        // Não permitir mudar planIdentifier
        if (updateData.planIdentifier) delete updateData.planIdentifier;

        const plan = await Plan.findByIdAndUpdate(planDbId, { $set: updateData }, { new: true, runValidators: true });
        if (!plan) return res.status(404).json({ success: false, message: "Plano não encontrado." });
        res.json({ success: true, message: "Plano atualizado.", plan });
    } catch (error) {
        res.status(500).json({ success: false, message: "Erro ao atualizar plano." });
        
    }
})
// DELETE /api/admin/plans/:planDbId (Deletar plano - CUIDADO: pode quebrar referências)
// Idealmente, apenas marcar como inativo (isActive: false)
apiRouter.delete('/admin/plans/:planDbId', protect, adminProtect, async (req, res) => {
    try {
        const plan = await Plan.findByIdAndDelete(req.params.planDbId);
        if (!plan) return res.status(404).json({ success: false, message: "Plano não encontrado." });
        res.json({ success: true, message: "Plano deletado." });
    } catch (error) {
        res.status(500).json({ success: false, message: "Erro ao deletar plano." });
    }
});

// --- Função para criar dados iniciais (Planos e AdminConfig) ---
async function initializeDefaultData() {
    try {
        // Verificar se já existe um AdminConfig
        let adminConfig = await AdminConfig.findOne({ configName: "mainConfig" });
        if (!adminConfig) {
            console.log("Criando configuração de administrador padrão...");
            adminConfig = new AdminConfig({
                configName: "mainConfig",
                paymentMethods: [
                    { methodIdentifier: "mpesa_padrao", name: "Mpesa Padrão", type: "mobile_money", address: "840000000", instructionsForUser: "Envie para o Mpesa e cole o ID.", withdrawalFeePercentage: 2 },
                    { methodIdentifier: "emola_padrao", name: "Emola Padrão", type: "mobile_money", address: "860000000", instructionsForUser: "Envie para o Emola e cole o ID.", withdrawalFeePercentage: 2.5 },
                    { methodIdentifier: "btc_main", name: "Bitcoin Principal", type: "crypto", currencyForCrypto: "BTC", network: "Bitcoin", address: "sua_carteira_btc_aqui", instructionsForUser: "Envie BTC e cole o TXID.", withdrawalFeePercentage: 1, minWithdrawal: 1000 /* Equivalente em MT */ },
                    { methodIdentifier: "usdt_trc20", name: "USDT (Rede TRC20)", type: "crypto", currencyForCrypto: "USDT", network: "TRC20", address: "sua_carteira_usdt_trc20_aqui", instructionsForUser: "Envie USDT na rede TRON (TRC20) e cole o TXID.", withdrawalFeePercentage: 1.5, minWithdrawal: 200 /* Equivalente em MT */ }
                ],
                siteTexts: [
                    { key: "login_contact_info", value: "Em caso de problemas, contate suporte@investelite.com", locationHint: "Login Page"},
                    { key: "register_security_note", value: "Guarde bem sua pergunta e resposta de segurança.", locationHint: "Register Page"}
                ],
                nextReferralSuffix: 1001
            });
            await adminConfig.save();
            console.log("Configuração de administrador padrão criada.");
        } else {
            console.log("Configuração de administrador já existe.");
        }
        // Verificar e criar planos padrão
        const defaultPlans = [
            { planIdentifier: "plan_500", name: "Plano de 500 MT", value: 500, dailyPercentage: 6.21, dailyProfitMT: 31.05, totalClaimsPerDay: 5, claimsSplit: [{currency: "MT", amount: 6.21}, {currency: "MT", amount: 6.21}, {currency: "BTC", amount: 0.000020}, {currency: "ETH", amount: 0.00030}, {currency: "USDT", amount: 1.00}], order: 1 },
            { planIdentifier: "plan_1000", name: "Plano de 1000 MT", value: 1000, dailyPercentage: 7.87, dailyProfitMT: 78.70, totalClaimsPerDay: 5, claimsSplit: [{currency: "MT", amount: 15.74}, {currency: "MT", amount: 15.74}, {currency: "BTC", amount: 0.000050}, {currency: "ETH", amount: 0.00070}, {currency: "USDT", amount: 2.50}], order: 2 },
            { planIdentifier: "plan_5000", name: "Plano de 5000 MT", value: 5000, dailyPercentage: 7.97, dailyProfitMT: 398.50, totalClaimsPerDay: 5, claimsSplit: [{currency: "MT", amount: 79.70}, {currency: "MT", amount: 79.70}, {currency: "BTC", amount: 0.000250}, {currency: "ETH", amount: 0.00350}, {currency: "USDT", amount: 12.50}], order: 3 },
            { planIdentifier: "plan_10000", name: "Plano de 10000 MT", value: 10000, dailyPercentage: 8.52, dailyProfitMT: 852.00, totalClaimsPerDay: 5, claimsSplit: [{currency: "MT", amount: 170.40}, {currency: "MT", amount: 170.40}, {currency: "BTC", amount: 0.000500}, {currency: "ETH", amount: 0.00700}, {currency: "USDT", amount: 25.00}], order: 4 },
            { planIdentifier: "plan_30000", name: "Plano de 30000 MT", value: 30000, dailyPercentage: 8.89, dailyProfitMT: 2667.00, totalClaimsPerDay: 5, claimsSplit: [{currency: "MT", amount: 533.40}, {currency: "MT", amount: 533.40}, {currency: "BTC", amount: 0.001500}, {currency: "ETH", amount: 0.02100}, {currency: "USDT", amount: 75.00}], order: 5 },
            { planIdentifier: "plan_70000", name: "Plano de 70000 MT", value: 70000, dailyPercentage: 9.21, dailyProfitMT: 6447.00, totalClaimsPerDay: 5, claimsSplit: [{currency: "MT", amount: 1289.40}, {currency: "MT", amount: 1289.40}, {currency: "BTC", amount: 0.003500}, {currency: "ETH", amount: 0.04900}, {currency: "USDT", amount: 175.00}], order: 6 }
        ];

        for (const planData of defaultPlans) {
            const existingPlan = await Plan.findOne({ planIdentifier: planData.planIdentifier });
            if (!existingPlan) {
                console.log(`Criando plano padrão: ${planData.name}`);
                const newPlan = new Plan(planData);
                await newPlan.save();
            }
        }
        console.log("Verificação de planos padrão concluída.");

        // Criar um usuário admin padrão se não existir
        const adminUserExists = await User.findOne({ role: 'admin' });
        if (!adminUserExists && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
            console.log("Criando usuário administrador padrão...");
            const adminUser = new User({
                name: 'Administrador',
                email: process.env.ADMIN_EMAIL,
                password: process.env.ADMIN_PASSWORD,
                securityQuestion: 'Qual o seu papel?',
                securityAnswer: 'admin', // Será hasheada
                role: 'admin',
                referralCode: 'ADMIN000', // Código de admin
                balance: 0, // Admin não tem saldo de usuário
                firstDepositMade: true // Para não ter restrições
            });
            await adminUser.save();
            console.log(`Usuário administrador padrão criado com email: ${process.env.ADMIN_EMAIL}`);
        } else if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
            console.warn("Variáveis ADMIN_EMAIL e ADMIN_PASSWORD não definidas no .env. Usuário admin não será criado automaticamente.");
        }
        } catch (error) {
        console.error("Erro ao inicializar dados padrão:", error);
    }
}
// DENTRO DA PARTE 4 DO SEU server.js, junto com outras rotas /api/admin
// (Lembre-se que apiRouter foi definido antes)

// GET /api/admin/notifications (Lista todas as notificações com paginação)
apiRouter.get('/admin/notifications', protect, adminProtect, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || ITEMS_PER_PAGE_NOTIFICATIONS; // Use a constante do frontend ou defina uma no backend
    // const userIdFilter = req.query.userId; // Para filtro futuro
    // const typeFilter = req.query.type;   // Para filtro futuro

    try {
        let query = {};
        // if (userIdFilter) query.user = userIdFilter;
        // if (typeFilter && typeFilter !== 'all') query.type = typeFilter;

        const totalNotifications = await Notification.countDocuments(query);
        const notifications = await Notification.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .populate('user', 'name email'); // Popula o usuário se a notificação for específica

        res.json({
            success: true,
            notifications,
            currentPage: page,
            totalPages: Math.ceil(totalNotifications / limit),
            totalNotifications
        });
    } catch (error) {
        console.error("Admin - Erro ao buscar notificações:", error);
        res.status(500).json({ success: false, message: "Erro ao buscar notificações." });
    }
});

// POST /api/admin/notifications (Admin cria uma notificação)
apiRouter.post('/admin/notifications', protect, adminProtect, async (req, res) => {
    const {
        title, message, fullMessage, type, displayType,
        isGlobal, user: userId, // 'user' no corpo da req será o userId
        actionUrl, actionText, expiresAt
    } = req.body;

    try {
        if (!title || !message) {
            return res.status(400).json({ success: false, message: "Título e mensagem são obrigatórios." });
        }

        const notificationData = {
            title, message, fullMessage, type, displayType, isGlobal,
            actionUrl, actionText, expiresAt
        };

        if (isGlobal === false || isGlobal === 'false') { // Checar string 'false' também
            if (!userId) {
                return res.status(400).json({ success: false, message: "ID do usuário é obrigatório para notificações não globais." });
            }
            // Valide se o userId existe (opcional, mas bom)
            const targetUser = await User.findById(userId);
            if (!targetUser) {
                return res.status(404).json({ success: false, message: "Usuário alvo não encontrado." });
            }
            notificationData.user = userId;
            notificationData.isGlobal = false;
        } else {
            notificationData.user = null;
            notificationData.isGlobal = true;
        }

        const newNotification = new Notification(notificationData);
        await newNotification.save();

        // Chamar sua função utilitária createNotification NÃO é necessário aqui, pois já estamos criando e salvando.
        // A menos que createNotification faça algo mais (como enviar WebSockets), que não parece ser o caso.

        res.status(201).json({ success: true, message: "Notificação criada com sucesso.", notification: newNotification });

    } catch (error) {
        console.error("Admin - Erro ao criar notificação:", error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ success: false, message: error.message });
        }
        res.status(500).json({ success: false, message: "Erro no servidor ao criar notificação." });
    }
});

// DELETE /api/admin/notifications/:notificationId (Admin deleta uma notificação)
apiRouter.delete('/admin/notifications/:notificationId', protect, adminProtect, async (req, res) => {
    try {
        const { notificationId } = req.params;
        const notification = await Notification.findByIdAndDelete(notificationId);

        if (!notification) {
            return res.status(404).json({ success: false, message: "Notificação não encontrada." });
        }
        res.json({ success: true, message: "Notificação deletada com sucesso." });
    } catch (error) {
        console.error("Admin - Erro ao deletar notificação:", error);
        res.status(500).json({ success: false, message: "Erro ao deletar notificação." });
    }
});

// ---------- MIDDLEWARE DE ERRO GENÉRICO (OPCIONAL) ----------
// Deve ser o último middleware
app.use((err, req, res, next) => {
    console.error("ERRO NÃO TRATADO:", err.stack);
    res.status(500).json({ success: false, message: 'Algo deu muito errado no servidor!' });
});


// ---------- INICIALIZAÇÃO DO SERVIDOR ----------
app.listen(PORT, async () => {
    console.log(`Servidor Node.js rodando na porta ${PORT}`);
    await initializeDefaultData(); // Chama a função para criar dados iniciais na primeira vez

    // Configurar Cron Job para resetar claims (simples setInterval para exemplo, use node-cron para produção)
    // A cada 24 horas, à meia-noite por exemplo. Este setInterval é apenas um exemplo.
    // Idealmente, node-cron: cron.schedule('0 0 * * *', resetAllUserDailyClaims);
    const twentyFourHoursInMs = 24 * 60 * 60 * 1000;
    // setInterval(resetAllUserDailyClaims, twentyFourHoursInMs);
    // console.log("Cron job para resetar claims diários configurado (exemplo simples).");
    // Uma execução inicial para garantir que os claims estejam corretos no primeiro dia
    // await resetAllUserDailyClaims();
});

// Montar o router da API no prefixo /api (já estava na Parte 2, mas precisa estar aqui no final)
app.use('/api', apiRouter);

// Rota catch-all para servir index.html para qualquer rota não API (se estiver usando roteamento do lado do cliente no front-end)
// No nosso caso, com múltiplos HTMLs, o express.static já trata. Mas se fosse SPA:
// app.get('*', (req, res) => {
//     res.sendFile(path.join(__dirname, 'public', 'index.html'));
// });
