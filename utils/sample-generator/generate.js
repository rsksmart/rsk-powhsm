const EventEmitter = artifacts.require("EventEmitter");
const sampleGenerator = require('./lib/sample-generator');

const SPACES = 2; // Indentation

module.exports = function(callback) {
    (async () => {
        const seed = process.argv[process.argv.length-1];

        process.stdout.write('Deploying EventEmitter... ');
        const eventEmitter = await EventEmitter.new();
        process.stdout.write(`DONE (@ ${eventEmitter.address})\n`);

        const generate = sampleGenerator(web3, eventEmitter);

        process.stdout.write(`Generating sample with seed \'${seed}\'... `);
        const sample = await generate('seed');
        process.stdout.write(`DONE, sample follows\n\n`);
        process.stdout.write(JSON.stringify(sample, null, SPACES));
        process.stdout.write('\n');

        callback();
    })();
};
