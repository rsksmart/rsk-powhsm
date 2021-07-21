fs = require('fs')

const retrieve = async function(client, total, path) {
    f = fs.openSync(path, 'a');
    let count = 0;
    let current = await client.eth.getBlockNumber();
    while (count < total) {
        const { hash } = await client.eth.getBlock(current);
        raw = await client.rskm.getRawBlockHeaderByHash(hash);
        fs.writeSync(f, `${current}:${raw}\n`);
        current--;
        count++;
    }
    fs.closeSync(f);
}

module.exports = {
    retrieve
}
