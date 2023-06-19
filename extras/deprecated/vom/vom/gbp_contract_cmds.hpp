/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __VOM_GBP_CONTRACT_CMDS_H__
#define __VOM_GBP_CONTRACT_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/gbp_contract.hpp"

#include <vapi/gbp.api.vapi.hpp>

namespace VOM {
namespace gbp_contract_cmds {

/**
 * A command class that creates or updates the GBP contract
 */
class create_cmd
  : public rpc_cmd<HW::item<uint32_t>, vapi::Gbp_contract_add_del>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<uint32_t>& item,
             scope_t scope,
             sclass_t sclass,
             sclass_t dclass,
             const handle_t& acl,
             const gbp_contract::gbp_rules_t& gbp_rules,
             const gbp_contract::ethertype_set_t& allowed_ethertypes);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const create_cmd& i) const;

private:
  const scope_t m_scope;
  const sclass_t m_sclass;
  const sclass_t m_dclass;
  const handle_t m_acl;
  const gbp_contract::gbp_rules_t& m_gbp_rules;
  const gbp_contract::ethertype_set_t& m_allowed_ethertypes;
};

/**
 * A cmd class that deletes a GBP contract
 */
class delete_cmd
  : public rpc_cmd<HW::item<uint32_t>, vapi::Gbp_contract_add_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<uint32_t>& item,
             scope_t scope,
             sclass_t sclass,
             sclass_t dclass);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const delete_cmd& i) const;

private:
  const scope_t m_scope;
  const sclass_t m_sclass;
  const sclass_t m_dclass;
};

/**
 * A cmd class that Dumps all the GBP contracts
 */
class dump_cmd : public VOM::dump_cmd<vapi::Gbp_contract_dump>
{
public:
  /**
   * Constructor
   */
  dump_cmd() = default;

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const dump_cmd& i) const;

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};
}; // namespace gbp_contract_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: OFF
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
