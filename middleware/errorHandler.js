const errorHandler = (err, req, res, next) => {
    const statusCode = err.statusCode || 500; // Default to 500 if not specified
    const message = err.message || 'Internal Server Error';

    // console.error(err.stack); // Log the error stack for debugging

    res.status(statusCode).json({
        status:false,
        message,
    });
};

module.exports = errorHandler;