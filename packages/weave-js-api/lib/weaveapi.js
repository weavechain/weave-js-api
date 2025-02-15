import NodeApi from './nodeapi.js'

class WeaveAPI {

    create(config) {
        if (config == null) return null;
        return new NodeApi(config)
    }
}

export default WeaveAPI;