/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shenyu.admin.controller;

import org.apache.shenyu.admin.utils.SoulResultMessage;
import org.apache.shenyu.register.common.config.SoulRegisterCenterConfig;
import org.apache.shenyu.register.common.dto.MetaDataRegisterDTO;
import org.apache.shenyu.register.server.api.SoulServerRegisterPublisher;
import org.apache.shenyu.register.server.api.SoulServerRegisterRepository;
import org.apache.shenyu.spi.Join;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collections;

/**
 * The type Soul client controller.
 *
 * @author xiaoyu
 */
@RequestMapping("/soul-client")
@Join
public class SoulHttpRegistryController implements SoulServerRegisterRepository {
    
    private SoulServerRegisterPublisher publisher;
    
    @Override
    public void init(final SoulServerRegisterPublisher publisher, final SoulRegisterCenterConfig config) {
        this.init(config);
        this.publisher = publisher;
    }
    
    /**
     * Register spring mvc string.
     *
     * @param metaDataRegisterDTO the meta data register dto
     * @return the string
     */
    @PostMapping("/springmvc-register")
    @ResponseBody
    public String registerSpringMvc(@RequestBody final MetaDataRegisterDTO metaDataRegisterDTO) {
        publish(metaDataRegisterDTO);
        return SoulResultMessage.SUCCESS;
    }
    
    /**
     * Register spring cloud string.
     *
     * @param metaDataRegisterDTO the meta data register dto
     * @return the string
     */
    @PostMapping("/springcloud-register")
    @ResponseBody
    public String registerSpringCloud(@RequestBody final MetaDataRegisterDTO metaDataRegisterDTO) {
        publish(metaDataRegisterDTO);
        return SoulResultMessage.SUCCESS;
    }
    
    /**
     * Register rpc string.
     *
     * @param metaDataRegisterDTO the meta data register dto
     * @return the string
     */
    @PostMapping("/dubbo-register")
    @ResponseBody
    public String registerRpc(@RequestBody final MetaDataRegisterDTO metaDataRegisterDTO) {
        publish(metaDataRegisterDTO);
        return SoulResultMessage.SUCCESS;
    }
    
    /**
     * Register sofa rpc string.
     *
     * @param metaDataRegisterDTO the meta data register dto
     * @return the string
     */
    @PostMapping("/sofa-register")
    @ResponseBody
    public String registerSofaRpc(@RequestBody final MetaDataRegisterDTO metaDataRegisterDTO) {
        publish(metaDataRegisterDTO);
        return SoulResultMessage.SUCCESS;
    }
    
    /**
     * Register tars rpc string.
     *
     * @param metaDataRegisterDTO the meta data register dto
     * @return the string
     */
    @PostMapping("/tars-register")
    @ResponseBody
    public String registerTarsRpc(@RequestBody final MetaDataRegisterDTO metaDataRegisterDTO) {
        publish(metaDataRegisterDTO);
        return SoulResultMessage.SUCCESS;
    }
    
    /**
     * Register grpc string.
     *
     * @param metaDataRegisterDTO the meta data register dto
     * @return the string
     */
    @PostMapping("/grpc-register")
    @ResponseBody
    public String registerGrpc(@RequestBody final MetaDataRegisterDTO metaDataRegisterDTO) {
        publish(metaDataRegisterDTO);
        return SoulResultMessage.SUCCESS;
    }

    /**
     * Register motan string.
     *
     * @param metaDataRegisterDTO the meta data register dto
     * @return the string
     */
    @PostMapping("/motan-register")
    @ResponseBody
    public String registerMotan(@RequestBody final MetaDataRegisterDTO metaDataRegisterDTO) {
        publish(metaDataRegisterDTO);
        return SoulResultMessage.SUCCESS;
    }
    
    private void publish(final MetaDataRegisterDTO metaDataRegisterDTO) {
        publisher.publish(Collections.singletonList(metaDataRegisterDTO));
    }
}
