// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "erc721a/contracts/ERC721A.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "operator-filter-registry/src/UpdatableOperatorFilterer.sol";

contract OGXNFT is
    Ownable,
    UpdatableOperatorFilterer,
    ERC2981,
    ERC721A,
    ReentrancyGuard
{
    struct Season {
        uint256 price;
        uint256 sellNum;
        uint256 start_time;
        uint256 end_time;
        uint256 limit;
    }

    struct WhitelistSeason {
        uint256 season;
        bytes32 merkleRoot;
    }

    using Strings for uint256;

    uint256 public constant MAX_SUPPLY = 10000;
    bool public allowBuy = true;

    uint256 private _seasonMapIndex = 2;
    mapping(uint256 => uint256) _indexSeasonMap;
    string private _hiddenMetadataURI;
    mapping(uint256 => string) public seasonUriMap;
    mapping(uint256 => mapping(address => mapping(uint256 => uint256)))
        public soldBoxesLimit; // type => address => seasonNum => buynum
    mapping(uint256 => uint256) private _tokenSeasonMap; // tokenId => season
    mapping(uint256 => mapping(uint256 => Season)) private _ogxSeasons; // seasonNum => type => FUNQSeason
    mapping(uint256 => WhitelistSeason) public whitelistSeasons; // season => WhitelistSeason
    mapping(uint256 => bool) private _lockTokens; //token => isLooked

    event TokenBorned(
        address indexed owner,
        uint256 startTokenId,
        uint256 quantity,
        uint256 season
    );
    event SetRemainingEvolved(
        uint256 indexed _season,
        uint256 indexed _type,
        uint256 _sellNum,
        uint256 _start_time,
        uint256 _end_time
    );
    event UpdateRemainingEvolved(
        uint256 indexed _season,
        uint256 indexed _type,
        uint256 _end_time,
        uint256 _limit
    );
    event WhitelistRetire(uint256 indexed _season);
    event AddToWhitelistEven(uint256 indexed _season, bytes32 _merkleRoot);
    event SeasonsRetire(uint256 indexed _season, uint256 indexed _type);
    event TokenLocked(uint256 indexed tokenId);
    event TokenUnlocked(uint256 indexed tokenId);
    event OpenBox(uint256 indexed season, string baseURI);

    error IsNoOwner();
    error SeasonURINotEmpty(uint256 seasonNum);
    error TokenIsLocked(uint256 tokenId);
    error TokenIsUnlocked(uint256 tokenId);
    error LockQueryForNonexistentToken();

    constructor(
        string memory hiddenMetadataURI,
        string memory name,
        string memory symbol,
        address filterRegistry,
        address subscribeRegistry
    )
        ERC721A(name, symbol)
        UpdatableOperatorFilterer(address(0), address(0), false)
    {
        _hiddenMetadataURI = hiddenMetadataURI;
        _initRetainSeason();
        _setDefaultRoyalty(msg.sender, 1000);
        operatorFilterRegistry = IOperatorFilterRegistry(filterRegistry);
        if (address(0) != filterRegistry) {
            operatorFilterRegistry.register(address(this));
            if (address(0) != subscribeRegistry) {
                operatorFilterRegistry.subscribe(
                    address(this),
                    subscribeRegistry
                );
            }
        }
        _indexSeasonMap[0] = 1;
        _indexSeasonMap[1] = 2;
    }

    // set init
    function setRemaining(
        uint256 _season,
        uint256 _type,
        uint256 _price,
        uint256 _sellNum,
        uint256 _start_time,
        uint256 _end_time,
        uint256 _limit
    ) external onlyOwner {
        require(_season > 2, "season invalid");
        require(_start_time > 0, "start time invalid");
        require((_end_time > _start_time), "end time invalid 1");
        require(_sellNum > 0, "sell num invalid");
        Season storage _FUNQSeason = _ogxSeasons[_season][_type];
        _FUNQSeason.price = _price;
        _FUNQSeason.sellNum = _sellNum;
        _FUNQSeason.start_time = _start_time;
        _FUNQSeason.end_time = _end_time;
        _FUNQSeason.limit = _limit;

        _indexSeasonMap[_seasonMapIndex] = _season;
        _seasonMapIndex = _seasonMapIndex + 1;

        emit SetRemainingEvolved(
            _season,
            _type,
            _sellNum,
            _start_time,
            _end_time
        );
    }

    function updateRemaining(
        uint256 _season,
        uint256 _type,
        uint256 _end_time,
        uint256 _limit
    ) external onlyOwner {
        require(_season > 2, "season invalid");
        Season storage _FUNQSeason = _ogxSeasons[_season][_type];
        require(_FUNQSeason.start_time > 0, "season not exist");
        require(
            (_end_time > _FUNQSeason.start_time),
            "end_time must over start_time"
        );
        _FUNQSeason.end_time = _end_time;
        _FUNQSeason.limit = _limit;
        emit UpdateRemainingEvolved(_season, _type, _end_time, _limit);
    }

    function retireRemaining(
        uint256 _season,
        uint256 _type
    ) external onlyOwner {
        require(_season > 2, "season invalid");
        delete (_ogxSeasons[_season][_type]);
        for (uint i = 2; i < _seasonMapIndex; i++) {
            if (_season == _indexSeasonMap[i]) {
                delete _indexSeasonMap[i];
                break;
            }
        }
        emit SeasonsRetire(_season, _type);
    }

    // Function to set the merkle root
    function addToWhitelist(
        uint256 _season,
        bytes32 _newMerkleRoot
    ) external onlyOwner {
        whitelistSeasons[_season].season = _season;
        whitelistSeasons[_season].merkleRoot = _newMerkleRoot;
        emit AddToWhitelistEven(
            whitelistSeasons[_season].season,
            whitelistSeasons[_season].merkleRoot
        );
    }

    function retireWhitelist(uint256 _season) external onlyOwner {
        delete (whitelistSeasons[_season]);
        emit WhitelistRetire(whitelistSeasons[_season].season);
    }

    function buyBox(
        uint256 _season,
        uint256 _type,
        uint256 num,
        bytes32[] calldata _merkleProof
    ) external payable {
        require(allowBuy, "buy disabled");
        require(_season > 2, "season invalid");
        require(num > 0, "number invalid");
        require(_nextTokenId() > 6, "tokenId not up");
        require(totalSupply() + num <= MAX_SUPPLY, "over max supply");
        Season storage season = _ogxSeasons[_season][_type];
        require(
            (season.start_time <= block.timestamp) &&
                (season.end_time >= block.timestamp),
            "not in the sale period"
        );
        require(season.sellNum > 0, "sold out");
        require(season.sellNum >= num, "not enough left");
        require(season.price * num <= msg.value, "ether invalid");
        address sender = _msgSender();
        if (_type == 1) {
            WhitelistSeason storage _whitelistSeason = whitelistSeasons[
                _season
            ];
            require(
                _whitelistSeason.season != 0,
                "whitelist season nonexistent"
            );
            bytes32 leaf = keccak256(abi.encodePacked(sender));
            require(
                MerkleProof.verify(
                    _merkleProof,
                    _whitelistSeason.merkleRoot,
                    leaf
                ),
                "not in the whitelist."
            );
        }
        // Check max box per user
        uint256 boughtBoxes = soldBoxesLimit[_type][sender][_season];
        uint256 totalBoxes = boughtBoxes + num;
        require(
            season.limit == 0 || season.limit >= totalBoxes,
            "reach the limit"
        );
        // Transfer payment
        refundIfOver(season.price * num);
        // Add user bought boxes
        soldBoxesLimit[_type][sender][_season] = totalBoxes;
        uint256 startTokenId = _nextTokenId();
        _mint(sender, num);
        season.sellNum = season.sellNum - num;
        _bornFUNQ(startTokenId, _season);
        emit TokenBorned(sender, startTokenId, num, _season);
    }

    function withdrawMoneyToAddress(
        address address_,
        uint256 value
    ) external onlyOwner nonReentrant {
        require(address(this).balance >= value, "withdraw too much");
        if (address(this).balance >= value) {
            payable(address_).transfer(value);
        }
    }

    function mintNFTToTeamMember(uint256 num, address to) external onlyOwner {
        require(allowBuy, "buy disabled");
        require(_nextTokenId() > 6, "tokenId not up");
        require(totalSupply() + num <= MAX_SUPPLY, "over max supply");
        // Add user bought boxes
        uint256 startTokenId = _nextTokenId();
        _mint(to, num);
        _bornFUNQ(startTokenId, 2);
        emit TokenBorned(to, startTokenId, num, 2);
    }

    function mintExtraNFT(uint256 num, address to) external onlyOwner {
        require(allowBuy, "buy disabled");
        require(totalSupply() + num <= MAX_SUPPLY, "over max supply");
        Season storage ogxSeason = _ogxSeasons[1][0];
        require(ogxSeason.sellNum > 0, "sold out");
        require(ogxSeason.sellNum >= num, "not enough left");
        uint256 startTokenId = _nextTokenId();
        _mint(to, num);
        ogxSeason.sellNum = ogxSeason.sellNum - num;
        _bornFUNQ(startTokenId, 1);
        emit TokenBorned(to, startTokenId, num, 1);
    }

    function lock(uint256[] calldata tokenIds) external {
        for (uint256 index = 0; index < tokenIds.length; index++) {
            uint256 tokenId = tokenIds[index];
            _checkTokenOwner(tokenId);
            if (_lockTokens[tokenId]) {
                revert TokenIsLocked(tokenId);
            }
            _lockTokens[tokenId] = true;
            emit TokenLocked(tokenId);
        }
    }

    function unlock(uint256[] calldata tokenIds) external {
        for (uint256 index = 0; index < tokenIds.length; index++) {
            uint256 tokenId = tokenIds[index];
            _checkTokenOwner(tokenId);
            if (!_lockTokens[tokenId]) {
                revert TokenIsUnlocked(tokenId);
            }
            delete _lockTokens[tokenId];
            emit TokenUnlocked(tokenId);
        }
    }

    function getLocked(uint256 tokenId) public view virtual returns (bool) {
        if (!_exists(tokenId)) {
            revert LockQueryForNonexistentToken();
        }
        return _lockTokens[tokenId];
    }

    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        if (tokenId < _startTokenId() || tokenId >= _nextTokenId()) {
            return string(abi.encodePacked(_hiddenMetadataURI, "0.json"));
        } else {
            string memory uri = _findBaseURI(tokenId);
            if (bytes(uri).length == 0) {
                return string(abi.encodePacked(_hiddenMetadataURI, "0.json"));
            } else {
                return
                    string(abi.encodePacked(uri, tokenId.toString(), ".json"));
            }
        }
    }

    function openBox(
        uint256 seasonNum,
        string calldata baseUri
    ) external onlyOwner {
        if (bytes(seasonUriMap[seasonNum]).length > 0) {
            revert SeasonURINotEmpty(seasonNum);
        }
        seasonUriMap[seasonNum] = baseUri;
        emit OpenBox(seasonNum, baseUri);
    }

    function setAll(string calldata baseUri) external onlyOwner {
        require(bytes(baseUri).length > 0, "baseUri is empty");
        for (uint i = 0; i < _seasonMapIndex; i++) {
            uint256 seasonNum = _indexSeasonMap[i];
            if (seasonNum > 0) {
                seasonUriMap[seasonNum] = baseUri;
                emit OpenBox(seasonNum, baseUri);
            }
        }
    }

    function setBaseURI(string memory hiddenMetadataURI) external onlyOwner {
        _hiddenMetadataURI = hiddenMetadataURI;
    }

    function setAllowBuy(bool allowBuy_) external onlyOwner {
        allowBuy = allowBuy_;
    }

    function getSeason(
        uint256 _season,
        uint256 _type
    ) external view returns (uint256, uint256, uint256, uint256, bool) {
        Season storage _FUNQSeason = _ogxSeasons[_season][_type];
        bool soldOut = (_FUNQSeason.sellNum == 0);
        return (
            _FUNQSeason.price,
            _FUNQSeason.start_time,
            _FUNQSeason.end_time,
            _FUNQSeason.limit,
            soldOut
        );
    }

    function refundIfOver(uint256 price) private {
        require(msg.value >= price, "need more eth");
        if (msg.value > price) {
            payable(msg.sender).transfer(msg.value - price);
        }
    }

    function setRoyaltyInfo(
        address receiver,
        uint96 feeBasisPoints
    ) external onlyOwner {
        _setDefaultRoyalty(receiver, feeBasisPoints);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC721A, ERC2981) returns (bool) {
        return
            ERC721A.supportsInterface(interfaceId) ||
            ERC2981.supportsInterface(interfaceId) ||
            super.supportsInterface(interfaceId);
    }

    // ========= OPERATOR FILTERER OVERRIDES =========

    function setApprovalForAll(
        address operator,
        bool approved
    ) public override(ERC721A) onlyAllowedOperatorApproval(operator) {
        super.setApprovalForAll(operator, approved);
    }

    function approve(
        address operator,
        uint256 tokenId
    ) public payable override(ERC721A) onlyAllowedOperatorApproval(operator) {
        super.approve(operator, tokenId);
    }

    function batchTransferFrom(
        address from,
        address to,
        uint256[] calldata tokens
    ) public payable onlyAllowedOperator(from) {
        for (uint256 index = 0; index < tokens.length; index++) {
            super.transferFrom(from, to, tokens[index]);
        }
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public payable override(ERC721A) onlyAllowedOperator(from) {
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public payable override(ERC721A) onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) public payable override(ERC721A) onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, tokenId, data);
    }

    function owner()
        public
        view
        virtual
        override(Ownable, UpdatableOperatorFilterer)
        returns (address)
    {
        return Ownable.owner();
    }

    // teammeber season is alway 0 and type is always 0
    function _initRetainSeason() private {
        Season storage extraSeason = _ogxSeasons[1][0];
        extraSeason.sellNum = 6;
        extraSeason.limit = 6;
    }

    function _startTokenId() internal view virtual override returns (uint256) {
        return 1;
    }

    function _bornFUNQ(uint256 startTokenId, uint256 season) private {
        _tokenSeasonMap[startTokenId] = season;
    }

    function _findBaseURI(
        uint256 tokenId
    ) internal view returns (string memory) {
        string memory foundUri;
        if (tokenId < _nextTokenId()) {
            uint256 startTokenId = _startTokenId();
            for (; tokenId >= startTokenId; tokenId--) {
                uint256 seasonNum = _tokenSeasonMap[tokenId];
                if (seasonNum > 0) {
                    foundUri = seasonUriMap[seasonNum];
                    return foundUri;
                }
            }
        }
        return foundUri;
    }

    function _beforeTokenTransfers(
        address from,
        address to,
        uint256 startTokenId,
        uint256 quantity
    ) internal virtual override {
        // if it is a Transfer or Burn, we always deal with one token, that is startTokenId
        if (from != address(0)) {
            if (_lockTokens[startTokenId]) {
                revert TokenIsLocked(startTokenId);
            }
        }
        super._beforeTokenTransfers(from, to, startTokenId, quantity);
    }

    function _afterTokenTransfers(
        address from,
        address to,
        uint256 startTokenId,
        uint256 quantity
    ) internal virtual override {
        // if it is a Transfer or Burn, we always deal with one token, that is startTokenId
        if (from != address(0)) {
            // clear locks
            delete _lockTokens[startTokenId];
        }
        super._afterTokenTransfers(from, to, startTokenId, quantity);
    }

    function _checkTokenOwner(uint256 tokenId) internal view {
        address tokenOwner = ownerOf(tokenId);
        if (msg.sender != tokenOwner) {
            revert IsNoOwner();
        }
    }
}
