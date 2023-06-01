import NodeApi from './nodeapi'

class WeaveAPI {

    create(config) {
        if (config == null) return null;
        return new NodeApi(config)
    }
}

export default WeaveAPI;